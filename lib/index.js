"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Promise = require("bluebird");
var bcrypt = require("bcrypt");
var shortid = require("shortid");
exports.Errors = {
    EMAIL_IN_USE: 'EMAIL_IN_USE',
    NOT_FOUND: 'NOT_FOUND',
    NOT_VERIFIED: 'NOT_VERIFIED',
    WRONG_PASSWORD: 'WRONG_PASSWORD',
};
;
var AccountService = (function () {
    function AccountService(db) {
        this.db = db;
    }
    AccountService.prototype.initialize = function () {
        return this.db.schema.createTableIfNotExists('account', function (table) {
            table.string('id').primary();
            table.string('name');
            table.string('email').unique().notNullable();
            table.string('hashpass').notNullable();
            table.string('reset_key'); //.unique();
            table.timestamp('verified_email_at');
            table.timestamp('changed_email_at');
            table.timestamp('reset_expire_at');
            table.timestamps();
        });
    };
    AccountService.prototype.signup = function (email, password) {
        var _this = this;
        return this.ensureEmailNotInUse(email)
            .then(function () {
            return _this.createAccount(email, password);
        });
    };
    AccountService.prototype.verifyEmail = function (email) {
        var now = new Date().getTime();
        return this.db('account')
            .where('email', email)
            .update({
            verified_email_at: now,
            updated_at: now,
        });
    };
    AccountService.prototype.signin = function (email, password, options) {
        var _this = this;
        if (options === void 0) { options = { mustHaveEmailVerified: false }; }
        return this.findOne({ email: email })
            .then(function (account) { return _this.ensureSamePassword(account, password); })
            .then(function (account) { return options.mustHaveEmailVerified ? _this.ensureVerifiedEmail(account) : account; });
    };
    AccountService.prototype.changeEmail = function (id, password, newEmail) {
        var _this = this;
        return this.findOne({ id: id })
            .then(function (account) { return _this.ensureSamePassword(account, password); })
            .then(function (account) { return _this.ensureEmailNotInUse(newEmail); })
            .then(function () {
            var now = new Date().getTime();
            return _this.db('account')
                .where('id', id)
                .update({
                email: newEmail,
                changed_email_at: now,
                updated_at: now,
            });
        });
    };
    AccountService.prototype.changePassword = function (id, password, newPassword) {
        var _this = this;
        return this.findOne({ id: id })
            .then(function (account) { return _this.ensureSamePassword(account, password); })
            .then(function () {
            return _this.db('account')
                .where('id', id)
                .update({
                hashpass: bcrypt.hashSync(newPassword, 10),
                updated_at: new Date().getTime(),
            });
        });
    };
    AccountService.prototype.generateResetKey = function (email, expireAt) {
        var _this = this;
        return this.findOne({ email: email })
            .then(function (account) {
            var resetKey = shortid.generate();
            return _this.db('account')
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
    AccountService.prototype.resetPassword = function (email, resetKey, newPassword) {
    };
    AccountService.prototype.createAccount = function (email, password) {
        var now = new Date().getTime();
        var account = {
            id: shortid.generate(),
            email: email,
            hashpass: bcrypt.hashSync(password, 10),
            verified_email_at: 0,
            changed_email_at: now,
            reset_expire_at: 0,
            created_at: now,
            updated_at: now,
        };
        return this.db('account').insert(account).then(function () { return account.id; });
    };
    AccountService.prototype.findOne = function (attributes) {
        return this.db('account')
            .select('*')
            .where(attributes)
            .then(function (accounts) {
            if (accounts.length !== 1) {
                return Promise.reject(exports.Errors.NOT_FOUND);
            }
            else {
                return accounts[0];
            }
        });
    };
    AccountService.prototype.ensureSamePassword = function (account, password) {
        if (!bcrypt.compareSync(password, account.hashpass)) {
            return Promise.reject(exports.Errors.WRONG_PASSWORD);
        }
        else {
            return Promise.resolve(account);
        }
    };
    AccountService.prototype.ensureVerifiedEmail = function (account) {
        if (account.verified_email_at < account.changed_email_at) {
            return Promise.reject(exports.Errors.NOT_VERIFIED);
        }
        else {
            return Promise.resolve(account);
        }
    };
    AccountService.prototype.ensureEmailNotInUse = function (email) {
        return this.db('account')
            .select('*')
            .where('email', email)
            .then(function (accounts) {
            if (accounts.length > 0) {
                return Promise.reject(exports.Errors.EMAIL_IN_USE);
            }
            else {
                return true;
            }
        });
    };
    return AccountService;
}());
exports.AccountService = AccountService;
