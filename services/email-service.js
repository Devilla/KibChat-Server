const sendgrid = require("@sendgrid/mail");

// Set the API key for the emailing service
sendgrid.setApiKey(process.env.SEND_GRID_API);

exports.sendVerificationEmail = (email, username, token) => {
    // Send the email
    sendgrid.send({
        from: "no-reply@kibchat.com",
        to: email,
        subject: "Account Verification Code",
        html: `
            <p>Hello ${username},</p><br>
            <p>To verify your account, please enter the following code:</p>
            <h2>${token}</h2>
            <p>Thanks,</p>
            <p>Kibchat Team</p>
        `
    });
};