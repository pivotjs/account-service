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
        id: 'account-0',
        email: 'account-0@example.com',
        hashpass: bcrypt.hashSync('pass-0', 10),
        verified_at: 0,
        changed_email_at: now,
        created_at: now,
        updated_at: now,
    }, {
        id: 'account-1',
        email: 'account-1@example.com',
        hashpass: bcrypt.hashSync('pass-1', 10),
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
                var email = 'account-0@example.com';
                var password = '123';
                return service.signup(email, password).catch(function (err) {
                    expect(err).toBe(__1.Errors.EMAIL_IN_USE);
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
        describe('with the wrong email', function () {
            it('should fail', function () {
                service.signin('wrong-email@example.com', 'pass-0')
                    .catch(function (err) {
                    expect(err).toBe(__1.Errors.NOT_FOUND);
                });
            });
        });
        describe('with the wrong password', function () {
            it('should fail', function () {
                service.signin(accounts[0].email, 'wrong-password')
                    .catch(function (err) {
                    expect(err).toBe(__1.Errors.WRONG_PASSWORD);
                });
            });
        });
        describe('with the wrong email and password', function () {
            it('should fail', function () {
                service.signin('wrong-email@example.com', 'wrong-password').catch(function (err) {
                    expect(err).toBe(__1.Errors.NOT_FOUND);
                });
            });
        });
        describe('with the right email/password of an unverified account, requiring a verified account', function () {
            it('should fail', function () {
                service.signin(accounts[0].email, 'pass-0', { mustBeVerified: true })
                    .catch(function (err) {
                    expect(err).toBe(__1.Errors.NOT_VERIFIED);
                });
            });
        });
        describe('with the right email/password of a verified account, requiring a verified account', function () {
            it('should signin', function () {
                service.signin(accounts[1].email, 'pass-1', { mustBeVerified: true })
                    .then(function (_account) {
                    expect(_account.id).toBe(accounts[1].id);
                    expect(_account.email).toBe(accounts[1].email);
                });
            });
        });
        describe('with the right email/password of an unverified account, not requiring a verified account', function () {
            it('should signin', function () {
                service.signin(accounts[0].email, 'pass-0')
                    .then(function (_account) {
                    expect(_account.id).toBe(accounts[0].id);
                    expect(_account.email).toBe(accounts[0].email);
                });
            });
        });
    });
    describe('.changeEmail', function () {
        describe('with the wrong id', function () {
            it('should fail', function () {
                return service.changeEmail('wrong-id', 'pass-0', 'account-00@example.com')
                    .catch(function (err) {
                    expect(err).toBe(__1.Errors.NOT_FOUND);
                });
            });
        });
        describe('with the wrong password', function () {
            it('should fail', function () {
                return service.changeEmail(accounts[0].id, 'wrong-pass', 'account-00@example.com')
                    .catch(function (err) {
                    expect(err).toBe(__1.Errors.WRONG_PASSWORD);
                });
            });
        });
        describe('with the right id/password, to an email already in use', function () {
            it('should fail', function () {
                return service.changeEmail(accounts[0].id, 'pass-0', 'account-1@example.com')
                    .catch(function (err) {
                    expect(err).toBe(__1.Errors.EMAIL_IN_USE);
                });
            });
        });
        describe('with the right id/password, to an email not in use', function () {
            it('should change the email', function () {
                return service.changeEmail(accounts[0].id, 'pass-0', 'account-00@example.com')
                    .then(function () {
                    return db('account').where('id', accounts[0].id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(_accounts[0].email).toBe('account-00@example.com');
                    });
                });
            });
        });
    });
});
