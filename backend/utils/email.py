from flask_mail import Message, Mail
from flask import current_app, render_template_string
import threading

mail = Mail()

def send_async_email(app, msg):
    """Send email asynchronously"""
    with app.app_context():
        mail.send(msg)

def send_email(subject, recipient, body_text, body_html=None):
    """Send an email to a recipient"""
    try:
        msg = Message(
            subject=subject,
            recipients=[recipient] if isinstance(recipient, str) else recipient,
            body=body_text,
            html=body_html or body_text
        )
        
        # Send asynchronously
        thread = threading.Thread(
            target=send_async_email,
            args=(current_app._get_current_object(), msg)
        )
        thread.start()
        return True
    except Exception as e:
        current_app.logger.error(f"Error sending email: {str(e)}")
        return False

def send_contact_form_email(name, email, phone, subject, message):
    """Send contact form email to admin"""
    admin_email = current_app.config['ADMIN_EMAIL']
    
    email_subject = f"New Contact Form Submission: {subject or 'No Subject'}"
    
    body_html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f5f5f5;">
                <h2 style="color: #5B21B6; border-bottom: 2px solid #3B82F6; padding-bottom: 10px;">
                    New Contact Form Submission
                </h2>
                
                <div style="background-color: white; padding: 20px; border-radius: 8px; margin-top: 20px;">
                    <h3 style="color: #5B21B6;">Contact Details:</h3>
                    <p><strong>Name:</strong> {name}</p>
                    <p><strong>Email:</strong> <a href="mailto:{email}">{email}</a></p>
                    <p><strong>Phone:</strong> {phone or 'Not provided'}</p>
                    <p><strong>Subject:</strong> {subject or 'Not provided'}</p>
                    
                    <h3 style="color: #5B21B6; margin-top: 20px;">Message:</h3>
                    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; border-left: 3px solid #3B82F6;">
                        {message}
                    </div>
                </div>
                
                <div style="text-align: center; margin-top: 30px; color: #666; font-size: 12px;">
                    <p>This email was sent from Nawi website contact form</p>
                </div>
            </div>
        </body>
    </html>
    """
    
    body_text = f"""
    New Contact Form Submission
    
    Name: {name}
    Email: {email}
    Phone: {phone or 'Not provided'}
    Subject: {subject or 'Not provided'}
    
    Message:
    {message}
    """
    
    return send_email(email_subject, admin_email, body_text, body_html)

def send_design_request_confirmation(name, email, service_type):
    """Send confirmation email for design request"""
    subject = "Your Design Request Has Been Received - Nawi"
    
    body_html = f"""
    <html>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f5f5f5;">
                <h2 style="color: #5B21B6; text-align: center;">Thank You for Your Request!</h2>
                
                <div style="background-color: white; padding: 20px; border-radius: 8px; margin-top: 20px;">
                    <p>Dear {name},</p>
                    
                    <p>We have received your design request for <strong>{service_type}</strong>.</p>
                    
                    <p>Our team will review your requirements and get back to you within 24 hours with a detailed proposal and timeline.</p>
                    
                    <h3 style="color: #5B21B6;">What's Next?</h3>
                    <ul>
                        <li>Our design team will analyze your requirements</li>
                        <li>We'll prepare a customized proposal for your project</li>
                        <li>You'll receive a detailed quote and timeline</li>
                        <li>Once approved, we'll start working on your design</li>
                    </ul>
                    
                    <p>If you have any urgent questions, feel free to contact us:</p>
                    <p>📧 Email: nawycompany@gmail.com</p>
                    <p>📱 WhatsApp: +201206315886</p>
                    
                    <div style="text-align: center; margin-top: 30px;">
                        <p style="color: #5B21B6; font-weight: bold;">Thank you for choosing Nawi!</p>
                        <p style="color: #666;">We're excited to bring your vision to life</p>
                    </div>
                </div>
            </div>
        </body>
    </html>
    """
    
    body_text = f"""
    Dear {name},
    
    Thank you for your design request!
    
    We have received your request for {service_type}.
    
    Our team will review your requirements and get back to you within 24 hours.
    
    Best regards,
    Nawi Team
    """
    
    return send_email(subject, email, body_text, body_html)