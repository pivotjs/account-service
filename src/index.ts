import * as Knex from 'knex';
import * as Promise from 'bluebird';
import * as bcrypt from 'bcrypt';
import * as shortid from 'shortid';

export const AuthenticationErrors = {
    EMAIL_IN_USE: 'EMAIL_IN_USE',
    NOT_FOUND: 'NOT_FOUND',
    NOT_VERIFIED: 'NOT_VERIFIED',
    WRONG_PASSWORD: 'WRONG_PASSWORD',
    EXPIRED_RESET_KEY: 'EXPIRED_RESET_KEY',
}

export interface UserAccount {
    id: string;
    email: string;
    hashpass: string;
    reset_key: string;
    failed_attempts: number;
    verified_email_at: number;
    changed_email_at: number;
    reset_expire_at: number;
    created_at: number;
    updated_at: number;
};

interface Config {
    maxFailedAttempts: number;
    delayOnMaxFailedAttempts: number;
}

export class AuthenticationService {
    private db: any;

    constructor(db: Knex) {
        this.db = db;
    }

    initialize(): Promise<void> {
        return this.db.schema.createTableIfNotExists('user_account', (table) => {
            table.string('id').primary();
            table.string('email').unique().notNullable();
            table.string('hashpass').notNullable();
            table.string('reset_key').unique().notNullable();
            table.integer('failed_attempts').notNullable();
            table.timestamp('verified_email_at');
            table.timestamp('changed_email_at');
            table.timestamp('reset_expire_at');
            table.timestamps();
        });
    }

    signup(email: string, password: string): Promise<string> {
        return this.ensureEmailNotInUse(email)
            .then(() => {
                return this.createAccount(email, password);
            });
    }

    verifyEmail(email: string) {
        const now = new Date().getTime();
        return this.db('user_account')
            .where('email', email)
            .update({
                verified_email_at: now,
                updated_at: now,
            });
    }

    signin(email: string, password: string, options = { mustHaveEmailVerified: false }): Promise<UserAccount> {
        return this.findOne({ email })
            .then((account: UserAccount) => {
                return this.ensureSamePassword(account, password)
                    .then(() => options.mustHaveEmailVerified ? this.ensureVerifiedEmail(account) : account)
                    .then(() => this.updateAccount(account.id, { failed_attempts: 0 }))
                    .then(() => account);
            });
    }

    changeEmail(id: string, password: string, newEmail: string) {
        const now = new Date().getTime();
        return this.findOne({ id })
            .then((account: UserAccount) => this.ensureSamePassword(account, password))
            .then((account: UserAccount) => this.ensureEmailNotInUse(newEmail))
            .then((account: UserAccount) => this.updateAccount(id, { email: newEmail, changed_email_at: now }));
    }

    changePassword(id: string, password: string, newPassword: string) {
        return this.findOne({ id })
            .then((account: UserAccount) => this.ensureSamePassword(account, password))
            .then((account: UserAccount) => this.updateAccount(id, { hashpass: bcrypt.hashSync(newPassword, 10) }));
    }

    generateResetKey(email: string, expireAt: number): Promise<string> {
        const resetKey = shortid.generate();
        return this.findOne({ email })
            .then((account: UserAccount) => this.updateAccount(account.id, { reset_key: resetKey, reset_expire_at: expireAt }))
            .then(() => resetKey);
    }

    resetPassword(email: string, resetKey: string, newPassword: string) {
        return this.findOne({ email, reset_key: resetKey })
            .then((account: UserAccount) => {
                if (new Date().getTime() > account.reset_expire_at) {
                    return Promise.reject(AuthenticationErrors.EXPIRED_RESET_KEY);
                } else {
                    return this.updateAccount(account.id, { hashpass: bcrypt.hashSync(newPassword, 10) });
                }
            });
    }

    private createAccount(email: string, password: string): Promise<string> {
        const now = new Date().getTime();
        const account: UserAccount = {
            id: shortid.generate(),
            email,
            hashpass: bcrypt.hashSync(password, 10),
            failed_attempts: 0,
            reset_key: shortid.generate(),
            verified_email_at: 0,
            changed_email_at: now,
            reset_expire_at: 0,
            created_at: now,
            updated_at: now,
        };
        return this.db('user_account').insert(account).then(() => account.id);
    }

    private updateAccount(id: string, fields: { [key: string]: any }) {
        return this.db('user_account')
            .where('id', id)
            .update(Object.assign({}, fields, {
                updated_at: new Date().getTime(),
            }));
    }

    private findOne(fields: { [key: string]: any }) {
        return this.db('user_account')
            .select('*')
            .where(fields)
            .then((accounts: UserAccount[]) => {
                if (accounts.length !== 1) {
                    return Promise.reject(AuthenticationErrors.NOT_FOUND);
                } else {
                    return accounts[0];
                }
            });
    }

    private ensureSamePassword(account: UserAccount, password: string): Promise<UserAccount> {
        if (!bcrypt.compareSync(password, account.hashpass)) {
            return this.updateAccount(account.id, { failed_attempts: account.failed_attempts + 1 })
                .then(() => Promise.reject(AuthenticationErrors.WRONG_PASSWORD));
        } else {
            return Promise.resolve(account);
        }
    }

    private ensureVerifiedEmail(account: UserAccount): Promise<UserAccount> {
        if (account.verified_email_at < account.changed_email_at) {
            return Promise.reject(AuthenticationErrors.NOT_VERIFIED);
        } else {
            return Promise.resolve(account);
        }
    }

    private ensureEmailNotInUse(email: string): Promise<boolean> {
        return this.db('user_account')
            .select('*')
            .where('email', email)
            .then((accounts: UserAccount[]) => {
                if (accounts.length > 0) {
                    return Promise.reject(AuthenticationErrors.EMAIL_IN_USE);
                } else {
                    return true;
                }
            });
    }
}
