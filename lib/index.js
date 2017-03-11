"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Promise = require("bluebird");
var bcrypt = require("bcrypt");
var shortid = require("shortid");
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
            table.timestamp('verified_at');
            table.timestamps();
        });
    };
    AccountService.prototype.signup = function (email, password) {
        var _this = this;
        return this.db('account')
            .select('*')
            .where('email', email)
            .then(function (records) {
            if (records.length > 0) {
                return Promise.reject('EMAIL_IN_USE');
            }
            else {
                return _this.createAccount(email, password);
            }
        });
    };
    AccountService.prototype.verify = function (email) {
        var now = new Date().getTime();
        return this.db('account')
            .where('email', email)
            .update({
            verified_at: now,
            updated_at: now,
        });
    };
    AccountService.prototype.createAccount = function (email, password) {
        var now = new Date().getTime();
        var account = {
            id: shortid.generate(),
            email: email,
            hashpass: bcrypt.hashSync(password, 10),
            created_at: now,
            updated_at: now,
        };
        return this.db('account').insert(account).then(function () { return account.id; });
    };
    return AccountService;
}());
exports.AccountService = AccountService;
