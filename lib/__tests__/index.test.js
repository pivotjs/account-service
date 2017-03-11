"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var Knex = require("knex");
var bcrypt = require("bcrypt");
var __1 = require("..");
var db = Knex({
    "debug": false,
    "useNullAsDefault": true,
    "dialect": "sqlite3",
    "connection": {
        "filename": ":memory:"
    }
});
var service = new __1.AccountService(db);
var now = new Date().getTime();
var accounts = [{
        id: 'account-1',
        email: 'account-1@example.com',
        hashpass: bcrypt.hashSync('pass-1', 10),
        verified_at: 0,
        changed_email_at: now,
        created_at: now,
        updated_at: now,
    }, {
        id: 'account-2',
        email: 'account-2@example.com',
        hashpass: bcrypt.hashSync('pass-2', 10),
        verified_at: now,
        changed_email_at: now,
        created_at: now,
        updated_at: now,
    }];
describe('AccountService', function () {
    beforeAll(function () {
        return service.initialize();
    });
    afterAll(db.destroy);
    beforeEach(function () {
        return db('account')
            .delete()
            .then(function () { return db('account').insert(accounts); });
    });
    expect(service).toBeDefined();
    describe('.signup', function () {
        describe('when the email is not in use', function () {
            it('should create a new account', function () {
                var email = 'account-3@example.com';
                var password = '123';
                return service.signup(email, password).then(function (id) {
                    expect(id).toBeDefined();
                    return db('account')
                        .select('*')
                        .where('id', id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(_accounts[0].email).toBe(email);
                        expect(bcrypt.compareSync(password, _accounts[0].hashpass)).toBeTruthy();
                    });
                });
            });
        });
        describe('when the email is already in use', function () {
            it('should not a new account', function () {
                var email = 'account-1@example.com';
                var password = '123';
                return service.signup(email, password).catch(function (err) {
                    expect(err).toBe(__1.Errors.signup.EMAIL_IN_USE);
                });
            });
        });
    });
    describe('.verify', function () {
        describe('with an unverified account', function () {
            it('should verify the account', function () {
                return service.verify(accounts[0].email).then(function () {
                    return db('account')
                        .select('*')
                        .where('id', accounts[0].id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(_accounts[0].id).toBe(accounts[0].id);
                        expect(_accounts[0].email).toBe(accounts[0].email);
                        expect(_accounts[0].verified_at).toBeGreaterThan(0);
                        expect(_accounts[0].verified_at / (60 * 1000)).toBeCloseTo(new Date().getTime() / (60 * 1000));
                    });
                });
            });
        });
    });
    describe('.signin', function () {
        describe('with the right email/password combination', function () {
            it('should signin', function () {
                service.signin(accounts[0].email, 'pass-1')
                    .then(function (_account) {
                    expect(_account.id).toBe(accounts[0].id);
                    expect(_account.email).toBe(accounts[0].email);
                });
            });
        });
        describe('with the wrong email', function () {
            it('should fail', function () {
                service.signin('wrong-email@example.com', 'pass-1')
                    .catch(function (err) {
                    expect(err).toBe(__1.Errors.signin.ACCOUNT_NOT_FOUND);
                });
            });
        });
        describe('with the wrong password', function () {
            it('should fail', function () {
                service.signin(accounts[0].email, 'wrong-password')
                    .catch(function (err) {
                    expect(err).toBe(__1.Errors.signin.WRONG_PASSWORD);
                });
            });
        });
        describe('with the wrong email and password', function () {
            it('should fail', function () {
                service.signin('wrong-email@example.com', 'wrong-password').catch(function (err) {
                    expect(err).toBe(__1.Errors.signin.ACCOUNT_NOT_FOUND);
                });
            });
        });
    });
});
