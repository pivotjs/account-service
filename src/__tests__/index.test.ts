import * as Knex from 'knex';
import * as bcrypt from 'bcrypt';
import { Account, AccountService, Errors } from '..';

const db = Knex({
    "debug": false,
    "useNullAsDefault": true,
    "dialect": "sqlite3",
    "connection": {
        "filename": ":memory:"
    }
});

const service = new AccountService(db);

const now = new Date().getTime();

const accounts: Account[] = [{
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

describe('AccountService', () => {
    beforeAll(() => {
        return service.initialize();
    });

    afterAll(db.destroy);

    beforeEach(() => {
        return db('account')
            .delete()
            .then(() => db('account').insert(accounts))
    });

    expect(service).toBeDefined();

    describe('.signup', () => {
        describe('when the email is not in use', () => {
            it('should create a new account', () => {
                const email = 'account-3@example.com';
                const password = '123';
                return service.signup(email, password).then((id: string) => {
                    expect(id).toBeDefined();
                    return db('account')
                        .select('*')
                        .where('id', id)
                        .then((_accounts: Account[]) => {
                            expect(_accounts.length).toBe(1);
                            expect(_accounts[0].email).toBe(email);
                            expect(bcrypt.compareSync(password, _accounts[0].hashpass)).toBeTruthy();
                        });
                });
            });
        });

        describe('when the email is already in use', () => {
            it('should not a new account', () => {
                const email = 'account-0@example.com';
                const password = '123';
                return service.signup(email, password).catch((err) => {
                    expect(err).toBe(Errors.signup.EMAIL_IN_USE);
                });
            });
        });
    });

    describe('.verify', () => {
        describe('with an unverified account', () => {
            it('should verify the account', () => {
                return service.verify(accounts[0].email).then(() => {
                    return db('account')
                        .select('*')
                        .where('id', accounts[0].id)
                        .then((_accounts: Account[]) => {
                            expect(_accounts.length).toBe(1);
                            expect(_accounts[0].id).toBe(accounts[0].id);
                            expect(_accounts[0].email).toBe(accounts[0].email);
                            expect(_accounts[0].verified_at).toBeGreaterThan(0);
                            expect(_accounts[0].verified_at / (60 * 1000)).toBeCloseTo(new Date().getTime() / (60 * 1000))
                        });
                });
            });
        });
    });

    describe('.signin', () => {
        describe('with the wrong email', () => {
            it('should fail', () => {
                service.signin('wrong-email@example.com', 'pass-0')
                    .catch((err: string) => {
                        expect(err).toBe(Errors.signin.ACCOUNT_NOT_FOUND);
                    });
            });
        });

        describe('with the wrong password', () => {
            it('should fail', () => {
                service.signin(accounts[0].email, 'wrong-password')
                    .catch((err: string) => {
                        expect(err).toBe(Errors.signin.WRONG_PASSWORD);
                    });
            });
        });

        describe('with the wrong email and password', () => {
            it('should fail', () => {
                service.signin('wrong-email@example.com', 'wrong-password').catch((err: string) => {
                    expect(err).toBe(Errors.signin.ACCOUNT_NOT_FOUND);
                });
            });
        });

        describe('with the right email/password of an unverified account, requiring a verified account', () => {
            it('should fail', () => {
                service.signin(accounts[0].email, 'pass-0', { isVerified: true })
                    .catch((err: string) => {
                        expect(err).toBe(Errors.signin.ACCOUNT_NOT_VERIFIED);
                    });
            });
        });

        describe('with the right email/password of a verified account, requiring a verified account', () => {
            it('should signin', () => {
                service.signin(accounts[1].email, 'pass-1', { isVerified: true })
                    .then((_account: Account) => {
                        expect(_account.id).toBe(accounts[1].id);
                        expect(_account.email).toBe(accounts[1].email);
                    });
            });
        });

        describe('with the right email/password of an unverified account, not requiring a verified account', () => {
            it('should signin', () => {
                service.signin(accounts[0].email, 'pass-0')
                    .then((_account: Account) => {
                        expect(_account.id).toBe(accounts[0].id);
                        expect(_account.email).toBe(accounts[0].email);
                    });
            });
        });
    });
});
