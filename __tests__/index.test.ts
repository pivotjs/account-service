import * as Knex from 'knex';
import * as bcrypt from 'bcrypt-nodejs';
import { UserAccount, AuthenticationService, AuthenticationServiceOptions, AuthenticationErrors } from '../src/index';

const db = Knex({
    "debug": false,
    "useNullAsDefault": true,
    "dialect": "sqlite3",
    "connection": {
        "filename": ":memory:"
    }
});

const service = new AuthenticationService(db);

const now = new Date().getTime();

function createUserAccount(n: number): UserAccount {
    return {
        id: `account-${n}`,
        email: `account-${n}@example.com`,
        hashpass: bcrypt.hashSync(`pass-${n}`),
        reset_key: `reset-${n}`,
        failed_attempts: 0,
        max_failed_attempts_at: 0,
        verified_email_at: 0,
        changed_email_at: now,
        reset_expire_at: 0,
        created_at: now,
        updated_at: now,
    }
}

const MINUTE = 60 * 1000;

const defaultOptions: AuthenticationServiceOptions = {
    requireVerifiedEmail: false,
    maxFailedAttempts: 3,
    maxFailedAttemptsDelay: 30 * MINUTE,
}

describe('AuthenticationService', () => {
    beforeAll(() => {
        return service.initialize();
    });

    afterAll(db.destroy);

    beforeEach(() => {
        return db('user_account').delete()
    });

    expect(service).toBeDefined();

    describe('.signup', () => {
        let account;

        beforeEach(() => {
            account = createUserAccount(1);
            return db('user_account').insert(account);
        });

        describe('when the email is not in use', () => {
            it('should create a new account', () => {
                const email = 'account-3@example.com';
                const password = '123';
                return service.signup(email, password).then((id: string) => {
                    expect(id).toBeDefined();
                    return db('user_account')
                        .select('*')
                        .where('id', id)
                        .then((_accounts: UserAccount[]) => {
                            expect(_accounts.length).toBe(1);
                            expect(_accounts[0].email).toBe(email);
                            expect(bcrypt.compareSync(password, _accounts[0].hashpass)).toBe(true);
                        })
                        .catch((err) => {
                            expect(err).toBeUndefined();
                        });
                });
            });
        });

        describe('when the email is already in use', () => {
            it('should not a new account', () => {
                const email = account.email;
                const password = '123';
                return service.signup(email, password).catch((err) => {
                    expect(err).toBe(AuthenticationErrors.EMAIL_IN_USE);
                });
            });
        });
    });

    describe('.verifyEmail', () => {
        let account;

        beforeEach(() => {
            account = createUserAccount(1);
            return db('user_account').insert(account);
        });

        describe('with an unverified email', () => {
            it('should verify the email', () => {
                return service.verifyEmail(account.email)
                    .then(() => {
                        return db('user_account')
                            .select('*')
                            .where('id', account.id)
                            .then((_accounts: UserAccount[]) => {
                                expect(_accounts.length).toBe(1);
                                expect(_accounts[0].id).toBe(account.id);
                                expect(_accounts[0].email).toBe(account.email);
                                expect(_accounts[0].verified_email_at).toBeGreaterThan(new Date().getTime() - (1 * MINUTE));
                                expect(_accounts[0].verified_email_at).toBeLessThan(new Date().getTime() + (1 * MINUTE));
                            });
                    })
                    .catch((err) => {
                        expect(err).toBeUndefined();
                    });
            });
        });
    });

    describe('.signin', () => {
        let account1, account2;

        beforeEach(() => {
            account1 = createUserAccount(1);
            account2 = createUserAccount(2);
            account2.verified_email_at = now;
            return db('user_account').insert([account1, account2]);
        });

        describe('with the wrong email', () => {
            it('should fail', () => {
                return service.signin('wrong-email@example.com', 'pass-1', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the wrong password', () => {
            it('should fail', () => {
                return service.signin(account1.email, 'wrong-password', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.WRONG_PASSWORD);
                    });
            });
        });

        describe('with the wrong email and password', () => {
            it('should fail', () => {
                return service.signin('wrong-email@example.com', 'wrong-password', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the right email/password of an unverified account, requiring a verified account', () => {
            it('should fail', () => {
                const options = Object.assign({}, defaultOptions, { requireVerifiedEmail: true });
                return service.signin(account1.email, 'pass-1', options)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_VERIFIED);
                    });
            });
        });

        describe('with the right email/password of an unverified account, not requiring a verified account', () => {
            it('should signin', () => {
                return service.signin(account1.email, 'pass-1', defaultOptions)
                    .then((_account: UserAccount) => {
                        expect(_account.id).toBe(account1.id);
                        expect(_account.email).toBe(account1.email);
                    })
                    .catch((err) => {
                        expect(err).toBeUndefined();
                    });
            });
        });

        describe('with the right email/password of a verified account, requiring a verified account', () => {
            it('should signin', () => {
                const options = Object.assign({}, defaultOptions, { requireVerifiedEmail: true });
                return service.signin(account2.email, 'pass-2', options)
                    .then((_account: UserAccount) => {
                        expect(_account.id).toBe(account2.id);
                        expect(_account.email).toBe(account2.email);
                    })
                    .catch((err) => {
                        expect(err).toBeUndefined();
                    });
            });
        });
    });

    describe('.changeEmail', () => {
        let account1, account2;

        beforeEach(() => {
            account1 = createUserAccount(1);
            account2 = createUserAccount(2);
            return db('user_account').insert([account1, account2]);
        });

        describe('with the wrong id', () => {
            it('should fail', () => {
                return service.changeEmail('wrong-id', 'pass-1', 'account-11@example.com', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the wrong password', () => {
            it('should fail', () => {
                return service.changeEmail(account1.id, 'wrong-pass', 'account-11@example.com', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.WRONG_PASSWORD);
                    });
            });
        });

        describe('with the right id/password, to an email already in use', () => {
            it('should fail', () => {
                return service.changeEmail(account1.id, 'pass-1', account2.email, defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.EMAIL_IN_USE);
                    });
            });
        });

        describe('with the right id/password, to an email not in use', () => {
            it('should change the email', () => {
                return service.changeEmail(account1.id, 'pass-1', 'account-11@example.com', defaultOptions)
                    .then(() => {
                        return db('user_account').where('id', account1.id)
                            .then((_accounts: UserAccount[]) => {
                                expect(_accounts.length).toBe(1);
                                expect(_accounts[0].email).toBe('account-11@example.com');
                                expect(_accounts[0].changed_email_at).toBeGreaterThan(_accounts[0].verified_email_at);
                                expect(_accounts[0].changed_email_at).toBeGreaterThan(new Date().getTime() - (1 * MINUTE));
                                expect(_accounts[0].changed_email_at).toBeLessThan(new Date().getTime() + (1 * MINUTE));
                            });
                    })
                    .catch((err) => {
                        expect(err).toBeUndefined();
                    });
            });
        });
    });

    describe('.changePassword', () => {
        let account;

        beforeEach(() => {
            account = createUserAccount(1);
            return db('user_account').insert(account);
        });

        describe('with the wrong id', () => {
            it('should fail', () => {
                return service.changePassword('wrong-id', 'pass-1', 'pass-11', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the wrong password', () => {
            it('should fail', () => {
                return service.changeEmail(account.id, 'wrong-pass', 'pass-11', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.WRONG_PASSWORD);
                    });
            });
        });

        describe('with the right id/password', () => {
            it('should change the password', () => {
                return service.changePassword(account.id, 'pass-1', 'pass-11', defaultOptions)
                    .then(() => {
                        return db('user_account').where('id', account.id)
                            .then((_accounts: UserAccount[]) => {
                                expect(_accounts.length).toBe(1);
                                expect(bcrypt.compareSync('pass-11', _accounts[0].hashpass)).toBe(true);
                            });
                    })
                    .catch((err) => {
                        expect(err).toBeUndefined();
                    });
            });
        });
    });

    describe('.generateResetKey', () => {
        const future = new Date().getTime() + (1 * MINUTE);
        let account;

        beforeEach(() => {
            account = createUserAccount(1);
            return db('user_account').insert(account);
        });

        describe('with the wrong email', () => {
            it('should fail', () => {
                return service.generateResetKey('wrong-email', future)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the right email', () => {
            it('should fail', () => {
                return service.generateResetKey(account.email, future)
                    .then((resetKey: string) => {
                        return db('user_account').where('id', account.id)
                            .then((_accounts: UserAccount[]) => {
                                expect(_accounts.length).toBe(1);
                                expect(_accounts[0].reset_key).toBe(resetKey);
                                expect(_accounts[0].reset_key.length).toBeGreaterThan(5);
                                expect(_accounts[0].reset_expire_at).toBe(future);
                            });
                    })
                    .catch((err) => {
                        expect(err).toBeUndefined();
                    });
            });
        });
    });

    describe('.resetPassword', () => {
        let account1, account2;

        beforeEach(() => {
            account1 = createUserAccount(1);
            account1.reset_expire_at = now - (1 * MINUTE);
            account2 = createUserAccount(2);
            account2.reset_expire_at = now + (1 * MINUTE);
            return db('user_account').insert([account1, account2]);
        });

        describe('with the wrong email', () => {
            it('should fail', () => {
                return service.resetPassword('wrong-email', account2.reset_key, 'pass-222', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the wrong resetKey', () => {
            it('should fail', () => {
                return service.resetPassword(account2.email, 'wrong-reset-key', 'pass-222', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the right email/resetKey, for an account with an expired resetKey', () => {
            it('should fail', () => {
                return service.resetPassword(account1.email, account1.reset_key, 'pass-111', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.EXPIRED_RESET_KEY);
                    });
            });
        });

        describe('with the right email/resetKey, for an account with a valid resetKey', () => {
            it('should change the password', () => {
                return service.resetPassword(account2.email, account2.reset_key, 'pass-222', defaultOptions)
                    .then(() => {
                        return db('user_account').where('id', account2.id)
                            .then((_accounts: UserAccount[]) => {
                                expect(_accounts.length).toBe(1);
                                expect(bcrypt.compareSync('pass-222', _accounts[0].hashpass)).toBe(true);
                            });
                    })
                    .catch((err) => {
                        expect(err).toBeUndefined();
                    });
            });
        });
    });

    describe('brute force attack', () => {
        const expectUserAccountState = (id, failed_attempts: number, max_failed_attempts_at: number) => {
            return db('user_account')
                .where('id', id)
                .then((_accounts: UserAccount[]) => {
                    expect(_accounts.length).toBe(1);
                    expect(_accounts[0].failed_attempts).toBe(failed_attempts);
                    expect(_accounts[0].max_failed_attempts_at / 1000).toBeCloseTo(max_failed_attempts_at / 1000);
                });
        }

        describe('.login first attempt with the wrong password', () => {
            let account: UserAccount;

            beforeEach(() => {
                account = createUserAccount(1);
                return db('user_account').insert(account);
            });

            it('should increment the failed attemps', () => {
                return service.signin(account.email, 'wrong-password', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.WRONG_PASSWORD);
                        return expectUserAccountState(account.id, 1, 0);
                    });
            });
        });

        describe('.login max attempts with the wrong password', () => {
            let account: UserAccount;

            beforeEach(() => {
                account = createUserAccount(1);
                account.failed_attempts = defaultOptions.maxFailedAttempts - 1;
                return db('user_account').insert(account);
            });

            it('should increment the failed attemps and update the failed attempt timestamp', () => {
                return service.signin(account.email, 'wrong-password', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.WRONG_PASSWORD);
                        return expectUserAccountState(account.id, defaultOptions.maxFailedAttempts, new Date().getTime());
                    });
            });
        });

        describe('.login during the delay', () => {
            let account: UserAccount;
            const past = new Date().getTime() - (10 * MINUTE);

            beforeEach(() => {
                account = createUserAccount(1);
                account.failed_attempts = defaultOptions.maxFailedAttempts;
                account.max_failed_attempts_at = past;
                return db('user_account').insert(account);
            });

            it('should not try to login', () => {
                return service.signin(account.email, 'wrong-password', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.MAX_FAILED_ATTEMPTS_DELAY);
                        return expectUserAccountState(account.id, defaultOptions.maxFailedAttempts, past);
                    });
            });
        });

        describe('.login after the delay with the wrong password', () => {
            let account: UserAccount;
            const past = new Date().getTime() - defaultOptions.maxFailedAttemptsDelay - 1;

            beforeEach(() => {
                account = createUserAccount(1);
                account.failed_attempts = defaultOptions.maxFailedAttempts;
                account.max_failed_attempts_at = past;
                return db('user_account').insert(account);
            });

            it('should increment the failed attemps and update the failed attempt timestamp', () => {
                return service.signin(account.email, 'wrong-password', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.WRONG_PASSWORD);
                        return expectUserAccountState(account.id, defaultOptions.maxFailedAttempts + 1, new Date().getTime());
                    });
            });
        });

        describe('.login after the delay, with the right password', () => {
            let account: UserAccount;
            const past = new Date().getTime() - defaultOptions.maxFailedAttemptsDelay - 1;

            beforeEach(() => {
                account = createUserAccount(1);
                account.failed_attempts = defaultOptions.maxFailedAttempts;
                account.max_failed_attempts_at = past;
                return db('user_account').insert(account);
            });

            it('should login and clear the failed attempts state', () => {
                return service.signin(account.email, 'pass-1', defaultOptions)
                    .then((_account: UserAccount) => {
                        expect(_account.id).toBe(account.id);
                        expect(_account.email).toBe(account.email);
                        return expectUserAccountState(account.id, 0, 0);
                    })
                    .catch((err) => {
                        expect(err).toBeUndefined();
                    });
            });
        });


        describe('.resetPassword during the delay', () => {
            let account: UserAccount;
            const past = new Date().getTime() - (10 * MINUTE);
            const future = new Date().getTime() + (10 * MINUTE);

            beforeEach(() => {
                account = createUserAccount(1);
                account.reset_expire_at = future;
                account.failed_attempts = defaultOptions.maxFailedAttempts;
                account.max_failed_attempts_at = past;
                return db('user_account').insert(account);
            });

            it('should not reset the password', () => {
                return service.resetPassword(account.email, account.reset_key, 'pass-222', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.MAX_FAILED_ATTEMPTS_DELAY);
                        return expectUserAccountState(account.id, defaultOptions.maxFailedAttempts, past);
                    });
            });
        });

        describe('.resetPassword afterAll the delay', () => {
            let account: UserAccount;
            const past = new Date().getTime() - defaultOptions.maxFailedAttemptsDelay - 1;
            const future = new Date().getTime() + (10 * MINUTE);

            beforeEach(() => {
                account = createUserAccount(1);
                account.reset_expire_at = future;
                account.failed_attempts = defaultOptions.maxFailedAttempts;
                account.max_failed_attempts_at = past;
                return db('user_account').insert(account);
            });

            it('should reset the password and clear the failed attempts state', () => {
                return service.resetPassword(account.email, account.reset_key, 'pass-222', defaultOptions)
                    .then(() => {
                        return db('user_account').where('id', account.id)
                            .then((_accounts: UserAccount[]) => {
                                expect(_accounts.length).toBe(1);
                                expect(bcrypt.compareSync('pass-222', _accounts[0].hashpass)).toBe(true);
                                return expectUserAccountState(account.id, 0, 0);
                            });
                    })
                    .catch((err) => {
                        expect(err).toBeUndefined();
                    });
            });
        });
    })
});
