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
var service = new __1.AuthenticationService({
    maxFailedAttempts: 3,
    delayOnMaxFailedAttempts: 10,
}, db);
var now = new Date().getTime();
var accounts = [{
        id: 'account-0',
        email: 'account-0@example.com',
        hashpass: bcrypt.hashSync('pass-0', 10),
        reset_key: 'reset-0',
        failed_attempts: 0,
        failed_attempt_at: 0,
        verified_email_at: 0,
        changed_email_at: now,
        reset_expire_at: 0,
        created_at: now,
        updated_at: now,
    }, {
        id: 'account-1',
        email: 'account-1@example.com',
        hashpass: bcrypt.hashSync('pass-1', 10),
        reset_key: 'reset-1',
        failed_attempts: 0,
        failed_attempt_at: 0,
        verified_email_at: now,
        changed_email_at: now,
        reset_expire_at: new Date().getTime() + (60 * 60 * 1000),
        created_at: now,
        updated_at: now,
    }];
describe('AuthenticationService', function () {
    beforeAll(function () {
        return service.initialize();
    });
    afterAll(db.destroy);
    beforeEach(function () {
        return db('user_account')
            .delete()
            .then(function () { return db('user_account').insert(accounts); });
    });
    expect(service).toBeDefined();
    describe('.signup', function () {
        describe('when the email is not in use', function () {
            it('should create a new account', function () {
                var email = 'account-3@example.com';
                var password = '123';
                return service.signup(email, password).then(function (id) {
                    expect(id).toBeDefined();
                    return db('user_account')
                        .select('*')
                        .where('id', id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(_accounts[0].email).toBe(email);
                        expect(bcrypt.compareSync(password, _accounts[0].hashpass)).toBe(true);
                    });
                });
            });
        });
        describe('when the email is already in use', function () {
            it('should not a new account', function () {
                var email = 'account-0@example.com';
                var password = '123';
                return service.signup(email, password).catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.EMAIL_IN_USE);
                });
            });
        });
    });
    describe('.verifyEmail', function () {
        describe('with an unverified email', function () {
            it('should verify the email', function () {
                return service.verifyEmail(accounts[0].email).then(function () {
                    return db('user_account')
                        .select('*')
                        .where('id', accounts[0].id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(_accounts[0].id).toBe(accounts[0].id);
                        expect(_accounts[0].email).toBe(accounts[0].email);
                        expect(_accounts[0].verified_email_at).toBeGreaterThan(0);
                        expect(_accounts[0].verified_email_at / (60 * 1000)).toBeCloseTo(new Date().getTime() / (60 * 1000));
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
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the wrong password', function () {
            it('should fail', function () {
                service.signin(accounts[0].email, 'wrong-password')
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.WRONG_PASSWORD);
                });
            });
        });
        describe('with the wrong email and password', function () {
            it('should fail', function () {
                service.signin('wrong-email@example.com', 'wrong-password').catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the right email/password of an unverified account, requiring a verified account', function () {
            it('should fail', function () {
                service.signin(accounts[0].email, 'pass-0', { mustHaveEmailVerified: true })
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_VERIFIED);
                });
            });
        });
        describe('with the right email/password of a verified account, requiring a verified account', function () {
            it('should signin', function () {
                service.signin(accounts[1].email, 'pass-1', { mustHaveEmailVerified: true })
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
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the wrong password', function () {
            it('should fail', function () {
                return service.changeEmail(accounts[0].id, 'wrong-pass', 'account-00@example.com')
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.WRONG_PASSWORD);
                });
            });
        });
        describe('with the right id/password, to an email already in use', function () {
            it('should fail', function () {
                return service.changeEmail(accounts[0].id, 'pass-0', 'account-1@example.com')
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.EMAIL_IN_USE);
                });
            });
        });
        describe('with the right id/password, to an email not in use', function () {
            it('should change the email', function () {
                return service.changeEmail(accounts[0].id, 'pass-0', 'account-00@example.com')
                    .then(function () {
                    return db('user_account').where('id', accounts[0].id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(_accounts[0].email).toBe('account-00@example.com');
                        expect(_accounts[0].changed_email_at / (60 * 1000)).toBeCloseTo(new Date().getTime() / (60 * 1000));
                        expect(_accounts[0].changed_email_at).toBeGreaterThan(_accounts[0].verified_email_at);
                    });
                });
            });
        });
    });
    describe('.changePassword', function () {
        describe('with the wrong id', function () {
            it('should fail', function () {
                return service.changePassword('wrong-id', 'pass-0', 'pass-00')
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the wrong password', function () {
            it('should fail', function () {
                return service.changeEmail(accounts[0].id, 'wrong-pass', 'pass-00')
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.WRONG_PASSWORD);
                });
            });
        });
        describe('with the right id/password', function () {
            it('should change the password', function () {
                return service.changePassword(accounts[0].id, 'pass-0', 'pass-00')
                    .then(function () {
                    return db('user_account').where('id', accounts[0].id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(bcrypt.compareSync('pass-00', _accounts[0].hashpass)).toBe(true);
                    });
                });
            });
        });
    });
    describe('.generateResetKey', function () {
        var future = new Date().getTime() + (60 * 1000);
        describe('with the wrong email', function () {
            it('should fail', function () {
                return service.generateResetKey('wrong-email', future)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the right email', function () {
            it('should fail', function () {
                return service.generateResetKey(accounts[0].email, future)
                    .then(function (resetKey) {
                    return db('user_account').where('id', accounts[0].id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(_accounts[0].reset_key).toBe(resetKey);
                        expect(_accounts[0].reset_key.length).toBeGreaterThan(5);
                        expect(_accounts[0].reset_expire_at).toBe(future);
                    });
                });
            });
        });
    });
    describe('.resetPassword', function () {
        describe('with the wrong email', function () {
            it('should fail', function () {
                return service.resetPassword('wrong-email', accounts[1].reset_key, 'pass-111')
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the wrong resetKey', function () {
            it('should fail', function () {
                return service.resetPassword(accounts[1].email, 'wrong-reset-key', 'pass-111')
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the right email/resetKey, for an account with an expired resetKey', function () {
            it('should fail', function () {
                return service.resetPassword(accounts[0].email, accounts[0].reset_key, 'pass-111')
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.EXPIRED_RESET_KEY);
                });
            });
        });
        describe('with the right email/resetKey, for an account with a valid resetKey', function () {
            it('should change the password', function () {
                return service.resetPassword(accounts[1].email, accounts[1].reset_key, 'pass-111')
                    .then(function () {
                    return db('user_account').where('id', accounts[1].id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(bcrypt.compareSync('pass-111', _accounts[0].hashpass)).toBe(true);
                    });
                });
            });
        });
    });
});
