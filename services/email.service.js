import { Resend } from "resend"

const resend = new Resend(process.env.RESEND_API_KEY)

export const sendVerificationEmail = async ( email, token ) => {
    const verificationUrl = 
    `${process.env.APP_URL}/auth/verify-email?token=${encodeURIComponent(token)}`

    const { data, error } = await resend.emails.send({
        from: process.env.EMAIL_FROM,
        to: email,
        subject: "Verify your email for Teaching-App",
        html: `
            <p>Welcome to Teaching App.</p>
			<p>Please verify your email address:</p>
			<p>
				<a href="${verificationUrl}">Verify email</a>
			</p>
			<p>This link expires in 15 minutes.</p>
        `
    })

    if(error){
        throw new Error(`Failed to send verification email: ${error.message}`)
    }
    return data
}