const express = require('express');
const router = express.Router();
const passport = require('passport');
const crypto = require('crypto');
const async = require('async');
const nodemailer = require('nodemailer');

//Requiring user model
const User = require('../models/usermodel');
const { request } = require('express');

// Check if user is logged in
function isAuthenticatedUser(req, res, next){
    if(req.isAuthenticated()){
        return next();
    }
    req.flash('error_msg', 'You have to log in to access this page.');
    res.redirect('/login');
}

//Get routes
router.get('/login', (req, res) => {
    res.render('login');
});

router.get('/signup', (req, res) => {
    res.render('signup');
});

router.get('/dashboard', isAuthenticatedUser, (req, res) => {
    res.render('dashboard');
});

router.get('/logout', isAuthenticatedUser, (req, res) => {
    req.logOut();
    req.flash('success_msg', 'You have been logged out.');
    res.redirect('/login');
});

router.get('/forgot', (req, res) => {
    res.render('forgot');
})

router.get('/reset/:token', (req, res) => {
    User.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: {$gt: Date.now() }})
        .then(user => {
            if(!user) {
                req.flash('error_msg', 'Password reset token is invalid or has expired');
                res.redirect('/forgot');
            }

            res.render('newpassword', {token: req.params.token});
        })
        .catch(err => {
            req.flash('error_msg', err);
            res.redirect('/forgot');
        }); 
});

router.get('/password/change', isAuthenticatedUser, (req, res) => {
    res.render('changepassword');
});

//Post routes
router.post('/login', passport.authenticate('local', {
    successRedirect: '/dashboard',
    failureRedirect: '/login',
    failureFlash: 'Invalid email or password. Try again!'
}));

router.post('/signup', (req, res) => {
    let {name, email, password} = req.body;

    let userData = {
        name: name,
        email: email
    };

    User.register(userData, password, (err, user) => {
        if(err) {
            req.flash('error_msg', 'ERROR: '+err);
            res.redirect('/signup');
        }
        passport.authenticate('local') (req, res, () => {
            req.flash('success_msg', 'Account created succesfully');
            res.redirect('/login');
        })
    });
});

router.post('/password/change', (req, res) => {
    if(req.body.password != req.body.confirmpassword){
        req.flash('error_msg', 'Passwords do not match, try again!');
        return res.redirect('/password/change');
    }

    User.findOne({email: req.user.email})
        .then(user => {
            user.setPassword(req.body.password, err => {
                user.save()
                    .then(user => {
                        req.flash('success_msg', 'Password changed succesfully');
                        res.redirect('/dashboard');
                    })
                    .catch(err => {
                        req.flash('error_msg', err);
                        res.redirect('/password/change');
                    })
            });
        });
});

//Routes to handle forgot password
router.post('/forgot', (req, res, next) => {
    let recoveryPassword = '';
    async.waterfall([
        (done) => {
            crypto.randomBytes(20, (err, buf) =>{
                let token = buf.toString('hex');
                done(err, token);
            })
        },
        (token, done) => {
            User.findOne({email: req.body.email})
                .then(user => {
                    if(!user){
                        req.flash('error_msg', 'User does not exist with this email.');
                        return res.redirect('/forgot');
                    }

                    user.resetPasswordToken = token;
                    user.resetPasswordExpires = Date.now() + 1800000 // 30min

                    user.save(err => {
                        done(err, token, user);
                    });
                })
                .catch(err => {
                    req.flash('error_msg', err);
                    res.redirect('/forgot');
                })
        },
        (token, user) => {
            let smtpTransport = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.GMAIL_EMAIL,
                    pass: process.env.GMAIL_PASSWORD
                }
            });

            let mailOptions = {
                to: user.email,
                from: 'Joaquin Farall joakinfarall@gmail.com',
                subject: 'Password Recovery from Auth Project',
                text: 'Please click the following link to recover your password: \n\n'+
                      'http://'+req.headers.host+'/reset/'+token+'\n\n'+
                      'If you did not request this please ignore this email.'
            };
            smtpTransport.sendMail(mailOptions, err => {
                req.flash('success_msg', 'Email send with further instructions');
                res.redirect('/forgot');
            });
        }

    ], err => {
        if(err) res.redirect('/forgot');
    });
});

router.post('/reset/:token', (req, res) => {
    async.waterfall([
        (done) => {
            User.findOne({resetPasswordToken: req.params.token, resetPasswordExpires: {$gt: Date.now()}})
                .then(user => {
                    if(!user) {
                        req.flash('error_msg', 'Password reset token is invalid or has expired');
                        res.redirect('/forgot');
                    }

                    if(req.body.password != req.body.confirmpassword){
                        req.flash('error_msg', 'Password do not match');
                        return res.redirect('/forgot');
                    }

                    user.setPassword(req.body.password, err => {
                        user.resetPasswordToken = undefined;
                        user.resetPasswordExpires = undefined;

                        user.save(err => {
                            req.logIn(user, err => {
                                done(err, user);
                            });
                        });
                    });
                })
                .catch(err => {
                    request.flash('error_msg', err)
                    res.redirect('/forgot')
                });
        },

        (user) => {
            let smtpTransport = nodemailer.createTransport({
                service: 'Gmail',
                auth: {
                    user: process.env.GMAIL_EMAIL,
                    pass: process.env.GMAIL_PASSWORD
                }
            });

            let mailOptions = {
                to: user.email,
                from: 'Joaquin Farall joakinfarall@gmail.com',
                subject: 'Confirmed changed password',
                text: 'Hello, '+user.name+'\n\n'+
                      'Your password has been changed succesfully for your account '+ user.email
            };

            smtpTransport.sendMail(mailOptions, err => {
                req.flash('success_msg', 'Your password has been changed succesfully');
                res.redirect('/login');
            });
        }

    ], err => {
        res.redirect('/login');
    });
});

module.exports = router;