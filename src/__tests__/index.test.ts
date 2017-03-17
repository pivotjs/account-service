import * as Knex from 'knex';
import * as bcrypt from 'bcrypt';
import { UserAccount, AuthenticationService, AuthenticationServiceOptions, AuthenticationErrors } from '..';

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
        hashpass: bcrypt.hashSync(`pass-${n}`, 10),
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

const defaultOptions: AuthenticationServiceOptions = {
    requireVerifiedEmail: false,
    maxFailedAttempts: 3,
    maxFailedAttemptsDelay: 30 * 60 * 1000,
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
                                expect(_accounts[0].verified_email_at).toBeGreaterThan(0);
                                expect(_accounts[0].verified_email_at / (60 * 1000)).toBeCloseTo(new Date().getTime() / (60 * 1000));
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
                service.signin('wrong-email@example.com', 'pass-1', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the wrong password', () => {
            it('should fail', () => {
                service.signin(account1.email, 'wrong-password', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.WRONG_PASSWORD);
                    });
            });
        });

        describe('with the wrong email and password', () => {
            it('should fail', () => {
                service.signin('wrong-email@example.com', 'wrong-password', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the right email/password of an unverified account, requiring a verified account', () => {
            it('should fail', () => {
                const options = Object.assign({}, defaultOptions, { requireVerifiedEmail: true });
                service.signin(account1.email, 'pass-1', options)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_VERIFIED);
                    });
            });
        });

        describe('with the right email/password of an unverified account, not requiring a verified account', () => {
            it('should signin', () => {
                service.signin(account1.email, 'pass-1', defaultOptions)
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
                service.signin(account2.email, 'pass-2', options)
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
                                expect(_accounts[0].changed_email_at / (60 * 1000)).toBeCloseTo(new Date().getTime() / (60 * 1000));
                                expect(_accounts[0].changed_email_at).toBeGreaterThan(_accounts[0].verified_email_at);
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
        const future = new Date().getTime() + (60 * 1000);
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
            account1.reset_expire_at = now - 10000;
            account2 = createUserAccount(2);
            account2.reset_expire_at = now + 10000;
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
});
