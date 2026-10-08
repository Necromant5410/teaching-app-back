import argon2 from "argon2"
import { pool } from "../config/database.js"
import { sendVerificationEmail } from "../services/email.service.js"
import crypto from "node:crypto"


export const register = async ( req, res ) => {

    const { email, password, fullName, role } = req.body

    if(!email || !password || !fullName || !role) {
        return res.status(400).json({
            error: "email, password, fullName and role are required"
        })
    }

    const normalizedEmail = email.trim().toLowerCase()

    if (!normalizedEmail) {
        return res.status(400).json({
            error: "Email is required"
	    })
    }

    const allowedRoles = ["student", "teacher"]

    if(!allowedRoles.includes(role)){
        return res.status(400).json({
            error: "Role must be student or teacher"
        })
    }

    const passwordHash = await argon2.hash(password, {
		type: argon2.argon2id
	})

    const verificationToken = crypto.randomBytes(32).toString("hex");

	const tokenHash = crypto
		.createHash("sha256")
		.update(verificationToken)
		.digest("hex");

    let client

    try {
        client = await pool.connect()

        await client.query("BEGIN")
        
        const existingUserResult = await client.query(
            `SELECT id, email_verified_at
            FROM users
            WHERE email = $1`,
            [normalizedEmail]
        )

        const existingUser = existingUserResult.rows[0]

        if(existingUser?.email_verified_at){
            await client.query("ROLLBACK")

            return res.status(409).json({
                error: "User with this email already exists"
            })
        }

        let userId

        if(!existingUser) {
            const userResult = await client.query(
                `INSERT INTO users (email, password_hash, role)
                VALUES ($1, $2, $3)
                RETURNING id`,
                [normalizedEmail, passwordHash, role]
            )

            userId = userResult.rows[0].id

            await client.query(
                `INSERT INTO profiles (user_id, full_name)
                VALUES ($1, $2)`,
                [userId, fullName]
            )
        } else {
            userId = existingUser.id
        }

        const pendingPasswordHash = existingUser
            ? passwordHash
            : null;

        const pendingFullName = existingUser
            ? fullName
            : null;

        const pendingRole = existingUser
            ? role
            : null;


        await client.query(
            `INSERT INTO email_verifications (
                user_id,
                token_hash,
                pending_password_hash,
                pending_full_name,
        		pending_role,
                expires_at
            )
            VALUES ($1, $2, $3, $4, $5, NOW() + INTERVAL '15 minutes')
            ON CONFLICT (user_id)
            DO UPDATE SET 
            token_hash = EXCLUDED.token_hash,
            pending_password_hash = EXCLUDED.pending_password_hash,
            pending_full_name = EXCLUDED.pending_full_name,
	    	pending_role = EXCLUDED.pending_role,
	    	expires_at = EXCLUDED.expires_at,
            created_at = NOW()`,
            [userId, tokenHash, pendingPasswordHash, pendingFullName, pendingRole]
        )

        await client.query("COMMIT")

    } catch (error) {
        if(client){
            await client.query("ROLLBACK")
        }

        if(error.code === "23505"){
            return res.status(409).json({
                error: "User with this email already exists"
            })
        }

        // временно
        console.error(error)

        return res.status(500).json({
			error: "Failed to register user"
        })
    } finally {
        client?.release()
    }

    // verification email message
    try {
        await sendVerificationEmail(
            normalizedEmail,
            verificationToken
        )
    } catch (error) {
        console.error(error);

        return res.status(500).json({
            error: "Registration started, but verification email could not be sent"
        })
    }

    return res.status(201).json({
        message: "Registration started. Please verify your email."
    })

}


export const verifyEmail = async (req, res) => {
    const { token } = req.query

    if(!token){
        return res.status(400).json({
            error: "Verification token is required"
        })
    }

    const tokenHash = crypto
        .createHash("sha256")
        .update(token)
        .digest("hex")

    let client

    try {
        client = await pool.connect()

        await client.query("BEGIN")
        
        const verificationResult = await client.query(
            `SELECT 
                user_id,
                pending_password_hash,
                pending_full_name,
                pending_role,
                expires_at
            FROM email_verifications
            WHERE token_hash = $1
            FOR UPDATE`,
            [tokenHash]
        )

        const verification = verificationResult.rows[0];

        if (!verification) {
			await client.query("ROLLBACK");

			return res.status(400).json({
				error: "Invalid verification token"
			})
		}

        if (new Date(verification.expires_at) <= new Date()) {
			await client.query("ROLLBACK");

			return res.status(400).json({
				error: "Verification token has expired"
			})
		}

        if (verification.pending_password_hash) {
			await client.query(
				`UPDATE users
				SET password_hash = $1,
					role = $2
				WHERE id = $3`,
				[
					verification.pending_password_hash,
					verification.pending_role,
					verification.user_id
				]
			)

            await client.query(
				`UPDATE profiles
				SET full_name = $1
				WHERE user_id = $2`,
				[
					verification.pending_full_name,
					verification.user_id
				]
			)
        }

        await client.query(
			`UPDATE users
			SET email_verified_at = NOW()
			WHERE id = $1`,
			[verification.user_id]
		)
        await client.query(
			`DELETE FROM email_verifications
			WHERE user_id = $1`,
			[verification.user_id]
		)


        await client.query("COMMIT");

		return res.status(200).json({
			message: "Email verified successfully"
		});
	} catch (error) {

		if (client) {
			await client.query("ROLLBACK");
		}

		console.error(error);

		return res.status(500).json({
			error: "Failed to verify email"
		});

	} finally {
		client?.release();
	}
}