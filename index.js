var jwt = require("jwt-simple");


function Simplejwt(secretObj, errorMessageObj ){
	this.secret = secretObj.secret; 
	this.errorMessage = {msg: errorMessageObj.message};
}

Simplejwt.prototype.setSecret = function(secret){
	this.secret = secret
}
Simplejwt.prototype.setErrorMessage = function(msg){
	this.errorMessage = {msg: msg}
}

//curry function, run it like this -> Simplejwt.authenticate(req,res) (function(req,res){ //do something...  })
Simplejwt.prototype.authenticate = function(req, res, next){
	if(!req.cookies.token){
		req.flash("errors", this.errorMessage)
		return res.redirect("/login")
	} 
	var token = req.cookies.token.split(' ')[0];

	var payload = jwt.decode(token, this.secret);
	if(!payload.sub){
		req.flash("errors", this.errorMessage)
		return res.redirect("/login")
	}
	
	next(req, res);	
}

Simplejwt.prototype.createSendToken = function  (req,res, user, next) {
	var payload = {
		iss: req.hostname, 
		sub: user.id
	};
	var token = jwt.encode(payload, this.secret);
	res.cookie('token', token, {maxAge: 24 * 60 * 60 * 1000});
	res.cookie('userId', user.id, {maxAge: 24 * 60 * 60 * 1000});
	next(null, token);
}

module.exports = Simplejwt;