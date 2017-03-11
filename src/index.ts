import * as Knex from 'knex';
import * as Promise from 'bluebird';
import * as bcrypt from 'bcrypt';
import * as shortid from 'shortid';

export interface Account {
    id: string;
    name?: string;
    email: string;
    hashpass: string;
    verified_at?: Date;
    created_at: Date;
    updated_at: Date;
};

export class AccountService {
    private db: any;

    constructor(db: Knex) {
        this.db = db;
    }

    initialize(): Promise<void> {
        console.log('initialize');

        return this.db.schema.createTableIfNotExists('account', (table) => {
            table.string('id').primary();
            table.string('name');
            table.string('email').unique().notNullable();
            table.string('hashpass').notNullable();
            table.timestamp('verified_at');
            table.timestamps();
        });
    }

    signup(email: string, password: string): Promise<string> {
        return this.db('account')
            .select('*')
            .where('email', email)
            .then((records: Account[]) => {
                if (records.length > 0) {
                    return Promise.reject('EMAIL_IN_USE');
                } else {
                    return this.createAccount(email, password);
                }
            })

    }

    private createAccount(email: string, password: string): Promise<string> {
        const now = new Date();
        const account: Account = {
            id: shortid.generate(),
            email,
            hashpass: bcrypt.hashSync(password, 10),
            created_at: now,
            updated_at: now,
        };
        return this.db('account').insert(account).then(() => account.id);
    }
}
