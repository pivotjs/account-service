import * as Knex from 'knex';
import * as Promise from 'bluebird';
import * as bcrypt from 'bcrypt';
import * as shortid from 'shortid';

export const AuthenticationErrors = {
    EMAIL_IN_USE: 'EMAIL_IN_USE',
    EXPIRED_RESET_KEY: 'EXPIRED_RESET_KEY',
    MAX_FAILED_ATTEMPTS_DELAY: 'MAX_FAILED_ATTEMPTS_DELAY',
    NOT_FOUND: 'NOT_FOUND',
    NOT_VERIFIED: 'NOT_VERIFIED',
    WRONG_PASSWORD: 'WRONG_PASSWORD',
}

export interface UserAccount {
    id: string;
    email: string;
    hashpass: string;
    reset_key: string;
    failed_attempts: number;
    max_failed_attempts_at: number;
    verified_email_at: number;
    changed_email_at: number;
    reset_expire_at: number;
    created_at: number;
    updated_at: number;
};

export interface AuthenticationServiceOptions {
    requireVerifiedEmail: boolean;
    maxFailedAttempts: number;
    maxFailedAttemptsDelay: number;
}

export class AuthenticationService {
    private db: Knex;

    constructor(db: Knex) {
        this.db = db;
    }

    initialize(): Promise<void> {
        return this.db.schema.createTableIfNotExists('user_account', (table) => {
            table.string('id', 14).primary();
            table.string('email').unique().notNullable();
            table.string('hashpass').notNullable();
            table.string('reset_key', 14).unique().notNullable();
            table.integer('failed_attempts').notNullable();
            table.timestamp('max_failed_attempts_at').notNullable();
            table.timestamp('verified_email_at').notNullable();
            table.timestamp('changed_email_at').notNullable();
            table.timestamp('reset_expire_at').notNullable();
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

    signin(email: string, password: string, options: AuthenticationServiceOptions): Promise<UserAccount> {
        return this.findOne({ email })
            .then((account: UserAccount) => {
                return this.ensureAfterFailedAttemptsDelay(account, options)
                    .then(() => this.ensureSamePassword(account, password, options))
                    .then(() => options.requireVerifiedEmail ? this.ensureVerifiedEmail(account) : account)
                    .then(() => this.updateAccount(account.id, { failed_attempts: 0 }))
                    .then(() => account);
            });
    }

    changeEmail(id: string, password: string, newEmail: string, options: AuthenticationServiceOptions) {
        const now = new Date().getTime();
        return this.findOne({ id })
            .then((account: UserAccount) => {
                return this.ensureSamePassword(account, password, options)
                    .then(() => this.ensureEmailNotInUse(newEmail))
                    .then(() => this.updateAccount(id, { email: newEmail, changed_email_at: now }));
            });
    }

    changePassword(id: string, password: string, newPassword: string, options: AuthenticationServiceOptions) {
        return this.findOne({ id })
            .then((account: UserAccount) => this.ensureSamePassword(account, password, options))
            .then((account: UserAccount) => this.updateAccount(id, { hashpass: bcrypt.hashSync(newPassword, 10) }));
    }

    generateResetKey(email: string, expireAt: number): Promise<string> {
        const resetKey = shortid.generate();
        return this.findOne({ email })
            .then((account: UserAccount) => this.updateAccount(account.id, { reset_key: resetKey, reset_expire_at: expireAt }))
            .then(() => resetKey);
    }

    resetPassword(email: string, resetKey: string, newPassword: string, options: AuthenticationServiceOptions) {
        return this.findOne({ email, reset_key: resetKey })
            .then((account: UserAccount) => {
                return this.ensureAfterFailedAttemptsDelay(account, options)
                    .then(() => this.ensureValidResetKey(account))
                    .then(() => this.updateAccount(account.id, {
                        hashpass: bcrypt.hashSync(newPassword, 10),
                        failed_attempts: 0,
                    }));
            });
    }

    private createAccount(email: string, password: string): Promise<string> {
        const now = new Date().getTime();
        const account: UserAccount = {
            id: shortid.generate(),
            email,
            hashpass: bcrypt.hashSync(password, 10),
            reset_key: shortid.generate(),
            failed_attempts: 0,
            max_failed_attempts_at: 0,
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

    private ensureVerifiedEmail(account: UserAccount): Promise<UserAccount> {
        if (account.verified_email_at < account.changed_email_at) {
            return Promise.reject(AuthenticationErrors.NOT_VERIFIED);
        } else {
            return Promise.resolve(account);
        }
    }

    private ensureAfterFailedAttemptsDelay(account: UserAccount, options: AuthenticationServiceOptions): Promise<UserAccount> {
        const now = new Date().getTime();
        const delayEnd = account.max_failed_attempts_at + options.maxFailedAttemptsDelay;

        if (delayEnd > now) {
            return Promise.reject(AuthenticationErrors.MAX_FAILED_ATTEMPTS_DELAY);
        } else {
            return Promise.resolve(account);
        }
    }

    private ensureSamePassword(account: UserAccount, password: string, options: AuthenticationServiceOptions): Promise<UserAccount> {
        if (bcrypt.compareSync(password, account.hashpass)) {
            return this.updateAccount(account.id, { failed_attempts: 0, max_failed_attempts_at: 0 }).then(() => account);
        } else {
            const update: any = {
                failed_attempts: account.failed_attempts + 1
            };

            if (update.failed_attempts >= options.maxFailedAttempts) {
                update.max_failed_attempts_at = new Date().getTime();
            }

            return this.updateAccount(account.id, update).then(() => Promise.reject(AuthenticationErrors.WRONG_PASSWORD));
        }
    }

    private ensureValidResetKey(account: UserAccount): Promise<UserAccount> {
        if (new Date().getTime() > account.reset_expire_at) {
            return Promise.reject(AuthenticationErrors.EXPIRED_RESET_KEY);
        } else {
            return Promise.resolve(account);
        }
    }
}
