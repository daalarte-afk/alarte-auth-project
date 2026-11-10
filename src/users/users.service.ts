import { Injectable } from '@nestjs/common';
import { DatabaseService } from '../database/database.service';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UsersService {
    constructor(private readonly db: DatabaseService) {}

    async createUser(username: string, password: string, role?: string) {
        const pool = this.db.getPool();
        const hashed_password = await bcrypt.hash(password, 10);
        const [result] = await pool.execute(
            'INSERT INTO users (username, hashed_password, role) VALUES (?, ?, ?)',
            [username, hashed_password, role || 'user'],
        ) as any;
        return { id: result.insertId, username, role: role || 'user' };
    }

    async getAll() {
        const pool = this.db.getPool();
        const [rows] = await pool.execute('SELECT id, username, role FROM users');
        return rows;
    }

    async findById(id: number) {
        const pool = this.db.getPool();
        const [rows] = await pool.execute(
            'SELECT id, username, role, hashed_password FROM users WHERE id = ?',
            [id],
        ) as any;
        return (rows as any[])[0] || null;
    }

    async findByUsername(username: string) {
        const pool = this.db.getPool();
        const [rows] = await pool.execute(
            'SELECT id, username, hashed_password, role FROM users WHERE username = ?',
            [username],
        ) as any;
        return (rows as any[])[0] || null;
    }

    async updateUser(id: number, body: { username?: string; password?: string; role?: string }) {
        const pool = this.db.getPool();
        const fields: string[] = [];
        const values: any[] = [];

        if (body.username) {
            fields.push('username = ?');
            values.push(body.username);
        }
        if (body.password) {
            fields.push('hashed_password = ?');
            values.push(await bcrypt.hash(body.password, 10));
        }
        if (body.role) {
            fields.push('role = ?');
            values.push(body.role);
        }

        if (fields.length === 0) return { updated: false };

        values.push(id);
        const [result] = await pool.execute(
            `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
            values,
        ) as any;
        return { updated: (result as any).affectedRows > 0 };
    }

    async deleteUser(id: number): Promise<{ affectedRows: number }> {
        const pool = this.db.getPool();
        const [result] = await pool.execute(
            'DELETE FROM users WHERE id = ?',
            [id],
        ) as any;
        return { affectedRows: (result as any).affectedRows };
    }

    async setRefreshToken(userId: number, token: string | null) {
        const pool = this.db.getPool();
        await pool.execute(
            'UPDATE users SET refresh_token = ? WHERE id = ?',
            [token, userId],
        );
    }

    async findByRefreshToken(token: string) {
        const pool = this.db.getPool();
        const [rows] = await pool.execute(
            'SELECT id, username, role FROM users WHERE refresh_token = ?',
            [token],
        ) as any;
        return (rows as any[])[0] || null;
    }
}

