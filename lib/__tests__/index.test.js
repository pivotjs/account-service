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
var service = new __1.AuthenticationService(db);
var now = new Date().getTime();
function createUserAccount(n) {
    return {
        id: "account-" + n,
        email: "account-" + n + "@example.com",
        hashpass: bcrypt.hashSync("pass-" + n, 10),
        reset_key: "reset-" + n,
        failed_attempts: 0,
        max_failed_attempts_at: 0,
        verified_email_at: 0,
        changed_email_at: now,
        reset_expire_at: 0,
        created_at: now,
        updated_at: now,
    };
}
var MINUTE = 60 * 1000;
var defaultOptions = {
    requireVerifiedEmail: false,
    maxFailedAttempts: 3,
    maxFailedAttemptsDelay: 30 * MINUTE,
};
describe('AuthenticationService', function () {
    beforeAll(function () {
        return service.initialize();
    });
    afterAll(db.destroy);
    beforeEach(function () {
        return db('user_account').delete();
    });
    expect(service).toBeDefined();
    describe('.signup', function () {
        var account;
        beforeEach(function () {
            account = createUserAccount(1);
            return db('user_account').insert(account);
        });
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
                    })
                        .catch(function (err) {
                        expect(err).toBeUndefined();
                    });
                });
            });
        });
        describe('when the email is already in use', function () {
            it('should not a new account', function () {
                var email = account.email;
                var password = '123';
                return service.signup(email, password).catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.EMAIL_IN_USE);
                });
            });
        });
    });
    describe('.verifyEmail', function () {
        var account;
        beforeEach(function () {
            account = createUserAccount(1);
            return db('user_account').insert(account);
        });
        describe('with an unverified email', function () {
            it('should verify the email', function () {
                return service.verifyEmail(account.email)
                    .then(function () {
                    return db('user_account')
                        .select('*')
                        .where('id', account.id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(_accounts[0].id).toBe(account.id);
                        expect(_accounts[0].email).toBe(account.email);
                        expect(_accounts[0].verified_email_at).toBeGreaterThan(0);
                        expect(_accounts[0].verified_email_at / (60 * 1000)).toBeCloseTo(new Date().getTime() / (60 * 1000));
                    });
                })
                    .catch(function (err) {
                    expect(err).toBeUndefined();
                });
            });
        });
    });
    describe('.signin', function () {
        var account1, account2;
        beforeEach(function () {
            account1 = createUserAccount(1);
            account2 = createUserAccount(2);
            account2.verified_email_at = now;
            return db('user_account').insert([account1, account2]);
        });
        describe('with the wrong email', function () {
            it('should fail', function () {
                return service.signin('wrong-email@example.com', 'pass-1', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the wrong password', function () {
            it('should fail', function () {
                return service.signin(account1.email, 'wrong-password', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.WRONG_PASSWORD);
                });
            });
        });
        describe('with the wrong email and password', function () {
            it('should fail', function () {
                return service.signin('wrong-email@example.com', 'wrong-password', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the right email/password of an unverified account, requiring a verified account', function () {
            it('should fail', function () {
                var options = Object.assign({}, defaultOptions, { requireVerifiedEmail: true });
                return service.signin(account1.email, 'pass-1', options)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_VERIFIED);
                });
            });
        });
        describe('with the right email/password of an unverified account, not requiring a verified account', function () {
            it('should signin', function () {
                return service.signin(account1.email, 'pass-1', defaultOptions)
                    .then(function (_account) {
                    expect(_account.id).toBe(account1.id);
                    expect(_account.email).toBe(account1.email);
                })
                    .catch(function (err) {
                    expect(err).toBeUndefined();
                });
            });
        });
        describe('with the right email/password of a verified account, requiring a verified account', function () {
            it('should signin', function () {
                var options = Object.assign({}, defaultOptions, { requireVerifiedEmail: true });
                return service.signin(account2.email, 'pass-2', options)
                    .then(function (_account) {
                    expect(_account.id).toBe(account2.id);
                    expect(_account.email).toBe(account2.email);
                })
                    .catch(function (err) {
                    expect(err).toBeUndefined();
                });
            });
        });
    });
    describe('.changeEmail', function () {
        var account1, account2;
        beforeEach(function () {
            account1 = createUserAccount(1);
            account2 = createUserAccount(2);
            return db('user_account').insert([account1, account2]);
        });
        describe('with the wrong id', function () {
            it('should fail', function () {
                return service.changeEmail('wrong-id', 'pass-1', 'account-11@example.com', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the wrong password', function () {
            it('should fail', function () {
                return service.changeEmail(account1.id, 'wrong-pass', 'account-11@example.com', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.WRONG_PASSWORD);
                });
            });
        });
        describe('with the right id/password, to an email already in use', function () {
            it('should fail', function () {
                return service.changeEmail(account1.id, 'pass-1', account2.email, defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.EMAIL_IN_USE);
                });
            });
        });
        describe('with the right id/password, to an email not in use', function () {
            it('should change the email', function () {
                return service.changeEmail(account1.id, 'pass-1', 'account-11@example.com', defaultOptions)
                    .then(function () {
                    return db('user_account').where('id', account1.id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(_accounts[0].email).toBe('account-11@example.com');
                        expect(_accounts[0].changed_email_at / (60 * 1000)).toBeCloseTo(new Date().getTime() / (60 * 1000));
                        expect(_accounts[0].changed_email_at).toBeGreaterThan(_accounts[0].verified_email_at);
                    });
                })
                    .catch(function (err) {
                    expect(err).toBeUndefined();
                });
            });
        });
    });
    describe('.changePassword', function () {
        var account;
        beforeEach(function () {
            account = createUserAccount(1);
            return db('user_account').insert(account);
        });
        describe('with the wrong id', function () {
            it('should fail', function () {
                return service.changePassword('wrong-id', 'pass-1', 'pass-11', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the wrong password', function () {
            it('should fail', function () {
                return service.changeEmail(account.id, 'wrong-pass', 'pass-11', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.WRONG_PASSWORD);
                });
            });
        });
        describe('with the right id/password', function () {
            it('should change the password', function () {
                return service.changePassword(account.id, 'pass-1', 'pass-11', defaultOptions)
                    .then(function () {
                    return db('user_account').where('id', account.id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(bcrypt.compareSync('pass-11', _accounts[0].hashpass)).toBe(true);
                    });
                })
                    .catch(function (err) {
                    expect(err).toBeUndefined();
                });
            });
        });
    });
    describe('.generateResetKey', function () {
        var future = new Date().getTime() + (60 * 1000);
        var account;
        beforeEach(function () {
            account = createUserAccount(1);
            return db('user_account').insert(account);
        });
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
                return service.generateResetKey(account.email, future)
                    .then(function (resetKey) {
                    return db('user_account').where('id', account.id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(_accounts[0].reset_key).toBe(resetKey);
                        expect(_accounts[0].reset_key.length).toBeGreaterThan(5);
                        expect(_accounts[0].reset_expire_at).toBe(future);
                    });
                })
                    .catch(function (err) {
                    expect(err).toBeUndefined();
                });
            });
        });
    });
    describe('.resetPassword', function () {
        var account1, account2;
        beforeEach(function () {
            account1 = createUserAccount(1);
            account1.reset_expire_at = now - 10000;
            account2 = createUserAccount(2);
            account2.reset_expire_at = now + 10000;
            return db('user_account').insert([account1, account2]);
        });
        describe('with the wrong email', function () {
            it('should fail', function () {
                return service.resetPassword('wrong-email', account2.reset_key, 'pass-222', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the wrong resetKey', function () {
            it('should fail', function () {
                return service.resetPassword(account2.email, 'wrong-reset-key', 'pass-222', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.NOT_FOUND);
                });
            });
        });
        describe('with the right email/resetKey, for an account with an expired resetKey', function () {
            it('should fail', function () {
                return service.resetPassword(account1.email, account1.reset_key, 'pass-111', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.EXPIRED_RESET_KEY);
                });
            });
        });
        describe('with the right email/resetKey, for an account with a valid resetKey', function () {
            it('should change the password', function () {
                return service.resetPassword(account2.email, account2.reset_key, 'pass-222', defaultOptions)
                    .then(function () {
                    return db('user_account').where('id', account2.id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(bcrypt.compareSync('pass-222', _accounts[0].hashpass)).toBe(true);
                    });
                })
                    .catch(function (err) {
                    expect(err).toBeUndefined();
                });
            });
        });
    });
    describe('brute force attack', function () {
        var expectUserAccountState = function (id, failed_attempts, max_failed_attempts_at) {
            return db('user_account')
                .where('id', id)
                .then(function (_accounts) {
                expect(_accounts.length).toBe(1);
                expect(_accounts[0].failed_attempts).toBe(failed_attempts);
                expect(_accounts[0].max_failed_attempts_at / 1000).toBeCloseTo(max_failed_attempts_at / 1000);
            });
        };
        describe('.login first attempt with the wrong password', function () {
            var account;
            beforeEach(function () {
                account = createUserAccount(1);
                return db('user_account').insert(account);
            });
            it('should increment the failed attemps', function () {
                return service.signin(account.email, 'wrong-password', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.WRONG_PASSWORD);
                    return expectUserAccountState(account.id, 1, 0);
                });
            });
        });
        describe('.login max attempts with the wrong password', function () {
            var account;
            beforeEach(function () {
                account = createUserAccount(1);
                account.failed_attempts = defaultOptions.maxFailedAttempts - 1;
                return db('user_account').insert(account);
            });
            it('should increment the failed attemps and update the failed attempt timestamp', function () {
                return service.signin(account.email, 'wrong-password', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.WRONG_PASSWORD);
                    return expectUserAccountState(account.id, defaultOptions.maxFailedAttempts, new Date().getTime());
                });
            });
        });
        describe('.login during the delay', function () {
            var account;
            var past = new Date().getTime() - (10 * MINUTE);
            beforeEach(function () {
                account = createUserAccount(1);
                account.failed_attempts = defaultOptions.maxFailedAttempts;
                account.max_failed_attempts_at = past;
                return db('user_account').insert(account);
            });
            it('should not try to login', function () {
                return service.signin(account.email, 'wrong-password', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.MAX_FAILED_ATTEMPTS_DELAY);
                    return expectUserAccountState(account.id, defaultOptions.maxFailedAttempts, past);
                });
            });
        });
        describe('.login after the delay with the wrong password', function () {
            var account;
            var past = new Date().getTime() - defaultOptions.maxFailedAttemptsDelay - 1;
            beforeEach(function () {
                account = createUserAccount(1);
                account.failed_attempts = defaultOptions.maxFailedAttempts;
                account.max_failed_attempts_at = past;
                return db('user_account').insert(account);
            });
            it('should increment the failed attemps and update the failed attempt timestamp', function () {
                return service.signin(account.email, 'wrong-password', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.WRONG_PASSWORD);
                    return expectUserAccountState(account.id, defaultOptions.maxFailedAttempts + 1, new Date().getTime());
                });
            });
        });
        describe('.login after the delay, with the right password', function () {
            var account;
            var past = new Date().getTime() - defaultOptions.maxFailedAttemptsDelay - 1;
            beforeEach(function () {
                account = createUserAccount(1);
                account.failed_attempts = defaultOptions.maxFailedAttempts;
                account.max_failed_attempts_at = past;
                return db('user_account').insert(account);
            });
            it('should login and clear the failed attempts state', function () {
                return service.signin(account.email, 'pass-1', defaultOptions)
                    .then(function (_account) {
                    expect(_account.id).toBe(account.id);
                    expect(_account.email).toBe(account.email);
                    return expectUserAccountState(account.id, 0, 0);
                })
                    .catch(function (err) {
                    expect(err).toBeUndefined();
                });
            });
        });
        describe('.resetPassword during the delay', function () {
            var account;
            var past = new Date().getTime() - (10 * MINUTE);
            var future = new Date().getTime() + (10 * MINUTE);
            beforeEach(function () {
                account = createUserAccount(1);
                account.reset_expire_at = future;
                account.failed_attempts = defaultOptions.maxFailedAttempts;
                account.max_failed_attempts_at = past;
                return db('user_account').insert(account);
            });
            it('should not reset the password', function () {
                return service.resetPassword(account.email, account.reset_key, 'pass-222', defaultOptions)
                    .catch(function (err) {
                    expect(err).toBe(__1.AuthenticationErrors.MAX_FAILED_ATTEMPTS_DELAY);
                    return expectUserAccountState(account.id, defaultOptions.maxFailedAttempts, past);
                });
            });
        });
        describe('.resetPassword afterAll the delay', function () {
            var account;
            var past = new Date().getTime() - defaultOptions.maxFailedAttemptsDelay - 1;
            var future = new Date().getTime() + (10 * MINUTE);
            beforeEach(function () {
                account = createUserAccount(1);
                account.reset_expire_at = future;
                account.failed_attempts = defaultOptions.maxFailedAttempts;
                account.max_failed_attempts_at = past;
                return db('user_account').insert(account);
            });
            it('should reset the password and clear the failed attempts state', function () {
                return service.resetPassword(account.email, account.reset_key, 'pass-222', defaultOptions)
                    .then(function () {
                    return db('user_account').where('id', account.id)
                        .then(function (_accounts) {
                        expect(_accounts.length).toBe(1);
                        expect(bcrypt.compareSync('pass-222', _accounts[0].hashpass)).toBe(true);
                        return expectUserAccountState(account.id, 0, 0);
                    });
                })
                    .catch(function (err) {
                    expect(err).toBeUndefined();
                });
            });
        });
    });
});
