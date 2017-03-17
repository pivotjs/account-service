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

const accounts: UserAccount[] = [{
    id: 'account-0',
    email: 'account-0@example.com',
    hashpass: bcrypt.hashSync('pass-0', 10),
    reset_key: 'reset-0',
    failed_attempts: 0,
    max_failed_attempts_at: 0,
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
    max_failed_attempts_at: 0,
    verified_email_at: now,
    changed_email_at: now,
    reset_expire_at: new Date().getTime() + (60 * 60 * 1000),
    created_at: now,
    updated_at: now,
}];

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
        return db('user_account')
            .delete()
            .then(() => db('user_account').insert(accounts))
    });

    expect(service).toBeDefined();

    describe('.signup', () => {
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
                        });
                });
            });
        });

        describe('when the email is already in use', () => {
            it('should not a new account', () => {
                const email = 'account-0@example.com';
                const password = '123';
                return service.signup(email, password).catch((err) => {
                    expect(err).toBe(AuthenticationErrors.EMAIL_IN_USE);
                });
            });
        });
    });

    describe('.verifyEmail', () => {
        describe('with an unverified email', () => {
            it('should verify the email', () => {
                return service.verifyEmail(accounts[0].email).then(() => {
                    return db('user_account')
                        .select('*')
                        .where('id', accounts[0].id)
                        .then((_accounts: UserAccount[]) => {
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

    describe('.signin', () => {
        describe('with the wrong email', () => {
            it('should fail', () => {
                service.signin('wrong-email@example.com', 'pass-0', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the wrong password', () => {
            it('should fail', () => {
                service.signin(accounts[0].email, 'wrong-password', defaultOptions)
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
                service.signin(accounts[0].email, 'pass-0', options)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_VERIFIED);
                    });
            });
        });

        describe('with the right email/password of a verified account, requiring a verified account', () => {
            it('should signin', () => {
                const options = Object.assign({}, defaultOptions, { requireVerifiedEmail: true });
                service.signin(accounts[1].email, 'pass-1', options)
                    .then((_account: UserAccount) => {
                        expect(_account.id).toBe(accounts[1].id);
                        expect(_account.email).toBe(accounts[1].email);
                    });
            });
        });

        describe('with the right email/password of an unverified account, not requiring a verified account', () => {
            it('should signin', () => {
                service.signin(accounts[0].email, 'pass-0', defaultOptions)
                    .then((_account: UserAccount) => {
                        expect(_account.id).toBe(accounts[0].id);
                        expect(_account.email).toBe(accounts[0].email);
                    });
            });
        });
    });

    describe('.changeEmail', () => {
        describe('with the wrong id', () => {
            it('should fail', () => {
                return service.changeEmail('wrong-id', 'pass-0', 'account-00@example.com', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the wrong password', () => {
            it('should fail', () => {
                return service.changeEmail(accounts[0].id, 'wrong-pass', 'account-00@example.com', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.WRONG_PASSWORD);
                    });
            });
        });

        describe('with the right id/password, to an email already in use', () => {
            it('should fail', () => {
                return service.changeEmail(accounts[0].id, 'pass-0', 'account-1@example.com', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.EMAIL_IN_USE);
                    });
            });
        });

        describe('with the right id/password, to an email not in use', () => {
            it('should change the email', () => {
                return service.changeEmail(accounts[0].id, 'pass-0', 'account-00@example.com', defaultOptions)
                    .then(() => {
                        return db('user_account').where('id', accounts[0].id)
                            .then((_accounts: UserAccount[]) => {
                                expect(_accounts.length).toBe(1);
                                expect(_accounts[0].email).toBe('account-00@example.com');
                                expect(_accounts[0].changed_email_at / (60 * 1000)).toBeCloseTo(new Date().getTime() / (60 * 1000));
                                expect(_accounts[0].changed_email_at).toBeGreaterThan(_accounts[0].verified_email_at);
                            });
                    });
            });
        });
    });

    describe('.changePassword', () => {
        describe('with the wrong id', () => {
            it('should fail', () => {
                return service.changePassword('wrong-id', 'pass-0', 'pass-00', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the wrong password', () => {
            it('should fail', () => {
                return service.changeEmail(accounts[0].id, 'wrong-pass', 'pass-00', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.WRONG_PASSWORD);
                    });
            });
        });

        describe('with the right id/password', () => {
            it('should change the password', () => {
                return service.changePassword(accounts[0].id, 'pass-0', 'pass-00', defaultOptions)
                    .then(() => {
                        return db('user_account').where('id', accounts[0].id)
                            .then((_accounts: UserAccount[]) => {
                                expect(_accounts.length).toBe(1);
                                expect(bcrypt.compareSync('pass-00', _accounts[0].hashpass)).toBe(true);
                            });
                    });
            });
        });
    });

    describe('.generateResetKey', () => {
        const future = new Date().getTime() + (60 * 1000);

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
                return service.generateResetKey(accounts[0].email, future)
                    .then((resetKey: string) => {
                        return db('user_account').where('id', accounts[0].id)
                            .then((_accounts: UserAccount[]) => {
                                expect(_accounts.length).toBe(1);
                                expect(_accounts[0].reset_key).toBe(resetKey);
                                expect(_accounts[0].reset_key.length).toBeGreaterThan(5);
                                expect(_accounts[0].reset_expire_at).toBe(future);
                            });
                    });
            });
        });
    });

    describe('.resetPassword', () => {
        describe('with the wrong email', () => {
            it('should fail', () => {
                return service.resetPassword('wrong-email', accounts[1].reset_key, 'pass-111', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the wrong resetKey', () => {
            it('should fail', () => {
                return service.resetPassword(accounts[1].email, 'wrong-reset-key', 'pass-111', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.NOT_FOUND);
                    });
            });
        });

        describe('with the right email/resetKey, for an account with an expired resetKey', () => {
            it('should fail', () => {
                return service.resetPassword(accounts[0].email, accounts[0].reset_key, 'pass-111', defaultOptions)
                    .catch((err: string) => {
                        expect(err).toBe(AuthenticationErrors.EXPIRED_RESET_KEY);
                    });
            });
        });

        describe('with the right email/resetKey, for an account with a valid resetKey', () => {
            it('should change the password', () => {
                return service.resetPassword(accounts[1].email, accounts[1].reset_key, 'pass-111', defaultOptions)
                    .then(() => {
                        return db('user_account').where('id', accounts[1].id)
                            .then((_accounts: UserAccount[]) => {
                                expect(_accounts.length).toBe(1);
                                expect(bcrypt.compareSync('pass-111', _accounts[0].hashpass)).toBe(true);
                            });
                    });
            });
        });
    });
});
