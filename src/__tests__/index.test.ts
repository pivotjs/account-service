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

describe('AccountService', () => {
    it('should be possible to create an instance', () => {
        expect(new AccountService(db)).toBeDefined();
    });
});

describe('AccountService.signup', () => {
    const service = new AccountService(db);

    const account: Account = {
        id: 'account-1',
        email: 'account-1@mailinator.com',
        hashpass: '123',
        created_at: new Date(),
        updated_at: new Date(),
    };

    beforeAll(() => {
        return service.initialize();
    });

    afterAll(db.destroy);

    beforeEach(() => {
        return db('account')
            .delete()
            .then(() => db('account').insert(account))
    });

    describe('when the email is not in use', () => {
        it('should create a new account', () => {
            const email = 'account-2@mailinator.com';
            const password = '123';
            return service.signup(email, password).then((id: string) => {
                expect(id).toBeDefined();
                return db('account')
                    .select('*')
                    .where('id', id)
                    .then((accounts: Account[]) => {
                        expect(accounts.length).toBe(1);
                        expect(accounts[0].email).toBe(email);
                        expect(bcrypt.compareSync(password, accounts[0].hashpass)).toBeTruthy();
                    });
            });
        });
    });


    describe('when the email is already in use', () => {
        it('should not a new account', () => {
            const email = 'account-1@mailinator.com';
            const password = '123';
            return service.signup(email, password).catch((err) => {
                expect(err).toBe('EMAIL_IN_USE');
            });
        });
    });
});
