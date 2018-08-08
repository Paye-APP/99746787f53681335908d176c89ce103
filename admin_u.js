"use-strict"
const debug = require('debug')('linkService:AdminUserDB')
const nedb = require('nedb')
const jwt = require('jsonwebtoken')
const crypto = require('crypto')
const path = require('path')
const fs = require('fs')
class AdminUser {
  /***
  **@desc {linkService admin database ops}
  **@api public
  **/
  constructor() {
    this.db_path = './db/admin_user.db'
    this.key = 'eU3@^-*3t1+y.7'
    this.algorithm = 'aes256'
    const self = this
    this.db = new nedb({filename:this.db_path,
      beforeDeserialization: function (doc) {
          let decipher = crypto.createDecipher(self.algorithm, self.key)

          try {
              let decrypted = decipher.update(doc, 'hex', 'utf8') + decipher.final('utf8')
              return JSON.parse(decrypted)
          } catch (e) {
              return doc
          }
      },
      afterSerialization: function (doc) {
        if (self.isJSON(doc)) {
            let cipher = crypto.createCipher(self.algorithm, self.key)
            let encrypted = cipher.update(JSON.stringify(doc), 'utf8', 'hex') + cipher.final('hex')
            return encrypted
        }
        return doc
    }
    })
    this.jwtPriv = fs.readFileSync(path.resolve(__dirname,'pem','server_jwt_priv.pem'))
    this.jwtPub = fs.readFileSync(path.resolve(__dirname,'pem','server_jwt_pub.pem'))
  }
  isJSON(thing) {
    thing = typeof thing !== "string" ? JSON.stringify(thing) : thing

    try {
        thing = JSON.parse(thing)
    } catch (e) {
        return false
    }

    if (typeof thing === "object" && thing !== null) {
        return true
    }

    return false
}
  openDatabase(){
      this.db.loadDatabase((err)=>{
          if (err) {
              debug('Failed to load Admin Database: error {%s}',err)
              return err
          }
          else {
              debug('Loaded the Admin database successfully: error {%s}',err)
              return true
          }
      })
  }
  login(name,pwdX,reqIP,callback){
    const self = this
    name = name.trim()
    debug('Login request for %s from ip:%s',name,reqIP)
    self.openDatabase()
    self.db.count({username:name,pwd:pwdX}, (err,count)=>{
      if(err || count < 1){
        if(typeof callback === 'function'){
          debug('Login for %s Failed,XPWD =%s',name,pwdX)
         return callback(err,null)
        }
        return false
      }
      const tsession = {
        username:name,
        ip:reqIP,
        last: Math.floor(Date.now()/1000)
      }
      self.db.update({username : name}, {$set : {session :{username:tsession.username,ip:tsession.ip, last:tsession.last}}},{multi : false},(err,affected)=> {
          if(err || affected < 1){
            if (typeof callback === 'function') {
              debug('Login for %s Failed,error=%s',name,err)
              return callback(err,null)
            }
            return false
          }
          self.generateToken(tsession,(err,token)=>{
            if(err){
              debug('Login for %s succeded,generateToken failed error :%s',name,err)
              return typeof callback ==='function' ? callback(err,null) : false
            }
            debug('Login for %s succeded,generateToken OK error: %s, token=%s',name,err,token)
            return typeof callback ==='function' ? callback(false,token) : token
          })

      })

    })


  }
  generateToken(payload, callback){
    debug('generateToken .. payload=%o',payload)
    const self = this
    jwt.sign(payload,self.jwtPriv,{
      expiresIn: Math.floor(Date.now()/1000) + (60*8),
      algorithm:'RS256'
    },
    (err, token)=>{
      return callback(err,token)
    })
  }
  authenticate(token,reqIP,callback){
    const self = this
    debug('authenticating admin claim from IP:%s and token %s',reqIP,token)
    if(typeof callback !== 'function') return false
    if(!token || token.toString().length < 10) return false
    jwt.verify(token,self.jwtPub,{algorithms:['RS256']},(err,payload)=>{
      if(err) {
        debug('admin claim from IP:%s could not be authenticated due to token error [%s]',reqIP,err)
        return callback(err,null)
      }
      self.openDatabase()
      self.db.find({$where:function(){return this.username == payload.username && this.session.last == payload.last} },(err,doc)=>{
        if(err){
          debug('admin claim failed due to database error: %s', err)
          return callback(err,null)
        }
        debug('token claim matched %d db records',doc.length)
        if(doc[0].session.ip != payload.ip || doc[0].session.last != payload.last){
          debug('admin claim failed due to evidence mismatch. (!IP || !last login)')
          return callback('false_token', null)
        }
        return callback(false,payload.username)
      })

    } )
  }
  logout(tokenORname, callback){
    const self = this
    debug('Logging out admin with username/token = %s', tokenORname)
    jwt.verify(tokenORname,self.jwtPub,{algorithms:['RS256']},(err,payload)=>{
      if (err) {
      self.db.update({username:tokenORname},{"session.last":null},(err1, affected)=>{
        if (err1) {
        return callback(err1, false)
        }
        debug("user logged out successfully")
        return callback(false,true)
      })
      }
      self.db.update({username:payload.username},{$set:{"session.last":null}},{multi:false},(err2, affected)=>{
        if (err2) {
        return callback(err2, false)
        }
        debug("user logged out successfully")
        return callback(false,true)
      })

    })
  }
  changePwd(token,ip,oldPwd, newPwd, callback){
    const self = this
    debug("Processing request for Password change by an admin user")
    self.authenticate(token,ip,(err,user)=>{
      if(err){
        debug("Error encountered while changing Password [%s]",err)
        return callback(err,false)
      }
      self.openDatabase()
      self.db.update({username:user,pwd:oldPwd},{$set:{pwd:newPwd}},{multi:false},(err,affected)=>{
        if(err){
          debug("Error encountered while changing Password [%s]",err)
          return callback(err,false)
        }
        if(affected < 1){
          debug("Error encountered while changing Password [database records were not changed] (%d collections affected)",affected)
          return callback('db_unchanged',false)
        }
        debug("User %s Password reset succeded",user)
        return callback(false,true)
      })
    })
  }
  formatDB(admin_uname){
    const self = this
    let default_u = {
    username :'admin_u'
    ,pwd :'*_y!PWN?'
    ,session: {
      username:'admin_u',
      last:0
      ,ip :'127.0.0.1'
    }
  }
  admin_uname = admin_uname.toString()
  admin_uname = admin_uname.replace(/ /,'' )
  if (admin_uname.length > 3){
    default_u.username = default_u.session.username = admin_uname
  }
  default_u.pwd = Math.random().toString(36).substr(2, 8)
  let ret = [null,null]
  self.openDatabase()
  self.db.remove({}, { multi: true }, (err, rmvd) => {
    if(!err || null == err){
      debug('AdminUser db removed %d documents', rmvd)
      self.db.insert(default_u,(e,doc) => {

        debug('AdminUser db inserted new document [ %o ] error returned = %s', doc,e)
        if(typeof doc === 'object'){

          console.log(`Admin Database formatted. \n new Username=${doc.username}\n new Password=${doc.pwd}`)
          this.db.count({}, function (err, count) { console.log('new db documents count ='+count)})
        }
      })
      return
    }
    debug('AdminUser db was unable to remove %d documents error: %s', rmvd, err)

})



  }
}
module.exports = AdminUser

