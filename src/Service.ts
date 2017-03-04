import * as Knex from 'knex';
import * as Promise from 'bluebird';
import * as bcrypt from 'bcrypt';
import * as shortid from 'shortid';
import { Account, Session } from './Types';

export class AccountService {
    private db: any;

    constructor(db: Knex) {
        this.db = db;
    }

    signup(email: string, password: string): Promise<Session> {
        return this.db('account')
            .select('*')
            .where('email', email)
            .then((records: Account[]) => {
                if (records.length > 0) {
                    return Promise.reject('EMAIL_IN_USE');
                } else {
                    return this.createAccount(email, password)
                }
            }).then((account: Account) => {
                return { accountId: account.id }
            });
    }

    private createAccount(email: string, password: string): Promise<Account> {
        const now = new Date();
        const account: Account = {
            id: shortid.generate(),
            email,
            hashpass: bcrypt.hashSync(password, 10),
            created_at: now,
            updated_at: now,
        };
        return this.db('account').insert(account).then(() => {
            return account;
        });
    }
}
