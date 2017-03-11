import * as Knex from 'knex';
import * as bcrypt from 'bcrypt';
import { Account, AccountService } from '..';

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
    id: 'account-1',
    email: 'account-1@example.com',
    hashpass: '123',
    created_at: now,
    updated_at: now,
}, {
    id: 'account-2',
    email: 'account-2@example.com',
    hashpass: '123',
    verified_at: now,
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
                const email = 'account-1@example.com';
                const password = '123';
                return service.signup(email, password).catch((err) => {
                    expect(err).toBe('EMAIL_IN_USE');
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
});
