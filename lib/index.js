"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Promise = require("bluebird");
var bcrypt = require("bcrypt");
var shortid = require("shortid");
exports.AuthenticationErrors = {
    EMAIL_IN_USE: 'EMAIL_IN_USE',
    NOT_FOUND: 'NOT_FOUND',
    NOT_VERIFIED: 'NOT_VERIFIED',
    WRONG_PASSWORD: 'WRONG_PASSWORD',
    EXPIRED_RESET_KEY: 'EXPIRED_RESET_KEY',
};
;
var AuthenticationService = (function () {
    function AuthenticationService(db) {
        this.db = db;
    }
    AuthenticationService.prototype.initialize = function () {
        return this.db.schema.createTableIfNotExists('user_account', function (table) {
            table.string('id').primary();
            table.string('name');
            table.string('email').unique().notNullable();
            table.string('hashpass').notNullable();
            table.string('reset_key').unique().notNullable();
            table.timestamp('verified_email_at');
            table.timestamp('changed_email_at');
            table.timestamp('reset_expire_at');
            table.timestamps();
        });
    };
    AuthenticationService.prototype.signup = function (email, password) {
        var _this = this;
        return this.ensureEmailNotInUse(email)
            .then(function () {
            return _this.createAccount(email, password);
        });
    };
    AuthenticationService.prototype.verifyEmail = function (email) {
        var now = new Date().getTime();
        return this.db('user_account')
            .where('email', email)
            .update({
            verified_email_at: now,
            updated_at: now,
        });
    };
    AuthenticationService.prototype.signin = function (email, password, options) {
        var _this = this;
        if (options === void 0) { options = { mustHaveEmailVerified: false }; }
        return this.findOne({ email: email })
            .then(function (account) { return _this.ensureSamePassword(account, password); })
            .then(function (account) { return options.mustHaveEmailVerified ? _this.ensureVerifiedEmail(account) : account; });
    };
    AuthenticationService.prototype.changeEmail = function (id, password, newEmail) {
        var _this = this;
        return this.findOne({ id: id })
            .then(function (account) { return _this.ensureSamePassword(account, password); })
            .then(function (account) { return _this.ensureEmailNotInUse(newEmail); })
            .then(function () {
            var now = new Date().getTime();
            return _this.db('user_account')
                .where('id', id)
                .update({
                email: newEmail,
                changed_email_at: now,
                updated_at: now,
            });
        });
    };
    AuthenticationService.prototype.changePassword = function (id, password, newPassword) {
        var _this = this;
        return this.findOne({ id: id })
            .then(function (account) { return _this.ensureSamePassword(account, password); })
            .then(function () {
            return _this.db('user_account')
                .where('id', id)
                .update({
                hashpass: bcrypt.hashSync(newPassword, 10),
                updated_at: new Date().getTime(),
            });
        });
    };
    AuthenticationService.prototype.generateResetKey = function (email, expireAt) {
        var _this = this;
        return this.findOne({ email: email })
            .then(function (account) {
            var resetKey = shortid.generate();
            return _this.db('user_account')
                .where('id', account.id)
                .update({
                reset_key: resetKey,
                reset_expire_at: expireAt,
                updated_at: new Date().getTime(),
            })
                .then(function () {
                return Promise.resolve(resetKey);
            });
        });
    };
    AuthenticationService.prototype.resetPassword = function (email, resetKey, newPassword) {
        var _this = this;
        return this.findOne({ email: email, reset_key: resetKey })
            .then(function (account) {
            if (new Date().getTime() > account.reset_expire_at) {
                return Promise.reject(exports.AuthenticationErrors.EXPIRED_RESET_KEY);
            }
            else {
                return _this.db('user_account')
                    .where('id', account.id)
                    .update({
                    hashpass: bcrypt.hashSync(newPassword, 10),
                    updated_at: new Date().getTime(),
                });
            }
        });
    };
    AuthenticationService.prototype.createAccount = function (email, password) {
        var now = new Date().getTime();
        var account = {
            id: shortid.generate(),
            email: email,
            hashpass: bcrypt.hashSync(password, 10),
            reset_key: shortid.generate(),
            verified_email_at: 0,
            changed_email_at: now,
            reset_expire_at: 0,
            created_at: now,
            updated_at: now,
        };
        return this.db('user_account').insert(account).then(function () { return account.id; });
    };
    AuthenticationService.prototype.findOne = function (attributes) {
        return this.db('user_account')
            .select('*')
            .where(attributes)
            .then(function (accounts) {
            if (accounts.length !== 1) {
                return Promise.reject(exports.AuthenticationErrors.NOT_FOUND);
            }
            else {
                return accounts[0];
            }
        });
    };
    AuthenticationService.prototype.ensureSamePassword = function (account, password) {
        if (!bcrypt.compareSync(password, account.hashpass)) {
            return Promise.reject(exports.AuthenticationErrors.WRONG_PASSWORD);
        }
        else {
            return Promise.resolve(account);
        }
    };
    AuthenticationService.prototype.ensureVerifiedEmail = function (account) {
        if (account.verified_email_at < account.changed_email_at) {
            return Promise.reject(exports.AuthenticationErrors.NOT_VERIFIED);
        }
        else {
            return Promise.resolve(account);
        }
    };
    AuthenticationService.prototype.ensureEmailNotInUse = function (email) {
        return this.db('user_account')
            .select('*')
            .where('email', email)
            .then(function (accounts) {
            if (accounts.length > 0) {
                return Promise.reject(exports.AuthenticationErrors.EMAIL_IN_USE);
            }
            else {
                return true;
            }
        });
    };
    return AuthenticationService;
}());
exports.AuthenticationService = AuthenticationService;
