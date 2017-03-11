import * as Knex from 'knex';
import * as Promise from 'bluebird';
import * as bcrypt from 'bcrypt';
import * as shortid from 'shortid';

export const Errors = {
    EMAIL_IN_USE: 'EMAIL_IN_USE',
    NOT_FOUND: 'NOT_FOUND',
    NOT_VERIFIED: 'NOT_VERIFIED',
    WRONG_PASSWORD: 'WRONG_PASSWORD',
}

export interface Account {
    id: string;
    email: string;
    hashpass: string;
    verified_at: number;
    changed_email_at: number;
    created_at: number;
    updated_at: number;
};

export class AccountService {
    private db: any;

    constructor(db: Knex) {
        this.db = db;
    }

    initialize(): Promise<void> {
        return this.db.schema.createTableIfNotExists('account', (table) => {
            table.string('id').primary();
            table.string('name');
            table.string('email').unique().notNullable();
            table.string('hashpass').notNullable();
            table.timestamp('verified_at');
            table.timestamp('changed_email_at');
            table.timestamps();
        });
    }

    signup(email: string, password: string): Promise<string> {
        return this.db('account')
            .select('*')
            .where('email', email)
            .then((records: Account[]) => {
                if (records.length > 0) {
                    return Promise.reject(Errors.EMAIL_IN_USE);
                } else {
                    return this.createAccount(email, password);
                }
            });
    }

    verify(email: string) {
        const now = new Date().getTime();
        return this.db('account')
            .where('email', email)
            .update({
                verified_at: now,
                updated_at: now,
            });
    }

    signin(email: string, password: string, options = { mustBeVerified: false }): Promise<Account> {
        return this.findOne({ email })
            .then((account: Account) => this.validatePassword(account, password))
            .then((account: Account) => this.validateIsVerified(account, options.mustBeVerified));
    }

    changeEmail(id: string, password: string, newEmail: string) {
        return this.findOne({ id })
            .then((account: Account) => this.validatePassword(account, password))
            .then((account: Account) => {
                const now = new Date().getTime();
                return this.db('account')
                    .where('id', id)
                    .update({
                        verified_at: now,
                        updated_at: now,
                    });
            });
    }

    changePassword(id: string, password: string, newPassword: string) {

    }

    requestResetPassword(email: string, expireAt: number) {

    }

    resetPassword(resetKey: string, newPassword: string) {

    }

    private createAccount(email: string, password: string): Promise<string> {
        const now = new Date().getTime();
        const account: Account = {
            id: shortid.generate(),
            email,
            hashpass: bcrypt.hashSync(password, 10),
            verified_at: 0,
            changed_email_at: now,
            created_at: now,
            updated_at: now,
        };
        return this.db('account').insert(account).then(() => account.id);
    }

    private findOne(attributes: { [key: string]: any }) {
        return this.db('account')
            .select('*')
            .where(attributes)
            .then((accounts: Account[]) => {
                if (accounts.length !== 1) {
                    return Promise.reject(Errors.NOT_FOUND);
                } else {
                    return accounts[0];
                }
            });
    }

    private validatePassword(account: Account, password: string): Promise<Account> {
        if (!bcrypt.compareSync(password, account.hashpass)) {
            return Promise.reject(Errors.WRONG_PASSWORD);
        } else {
            return Promise.resolve(account);
        }
    }

    private validateIsVerified(account: Account, mustBeVerified = false): Promise<Account> {
        if (mustBeVerified === true && account.verified_at < account.changed_email_at) {
            return Promise.reject(Errors.NOT_VERIFIED);
        } else {
            return Promise.resolve(account);
        }
    }
}
