#!/bin/bash

# Ultimate Email Sending Script with DKIM and Security Checks
# Version 2.1 - Fully Audited and Hardened

# Global variables
LOG_FILE="email_send_$(date +%Y%m%d).log"
ERROR_LOG="email_errors_$(date +%Y%m%d).log"
DKIM_KEYS_DIR="/etc/opendkim/keys"

# Check for required tools
check_dependencies() {
    local required=("sudo" "apt-get" "systemctl" "postconf" "opendkim-genkey" "sendmail")
    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Error: Required command '$cmd' not found" >&2
            exit 1
        fi
    done
}

# Validate script is not run as root but has sudo privileges
check_privileges() {
    if [ "$(id -u)" -eq 0 ]; then
        echo "SECURITY WARNING: This script should not be run as root!" >&2
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi

    if ! sudo -v; then
        echo "Error: User doesn't have sudo privileges" >&2
        exit 1
    fi
}

# Validate email format with stricter rules
validate_email() {
    local email="$1"
    local regex="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$"
    [[ $email =~ $regex ]] && return 0 || return 1
}

# Validate domain MX records
check_domain_mx() {
    local domain="$1"
    if ! dig +short MX "$domain" | grep -q .; then
        echo "WARNING: No MX records found for domain $domain"
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        [[ ! $REPLY =~ ^[Yy]$ ]] && exit 1
    fi
}

# Install required packages with error checking
install_dependencies() {
    echo "[$(date)] Installing dependencies..." | tee -a "$LOG_FILE"

    if ! sudo apt-get update -y >> "$LOG_FILE" 2>> "$ERROR_LOG"; then
        echo "Error: Failed to update packages" | tee -a "$ERROR_LOG"
        exit 1
    fi

    local packages=(
        postfix mailutils tmux dos2unix curl libsasl2-modules 
        opendkim opendkim-tools dnsutils
    )

    if ! sudo apt-get install -y "${packages[@]}" >> "$LOG_FILE" 2>> "$ERROR_LOG"; then
        echo "Error: Failed to install required packages" | tee -a "$ERROR_LOG"
        exit 1
    fi
}

# Configure DKIM with enhanced settings
configure_dkim() {
    local domain="$1"
    local selector="mail$(date +%m%d)"
    
    echo "[$(date)] Configuring DKIM for domain: $domain" | tee -a "$LOG_FILE"

    # Create directory structure
    sudo mkdir -p "$DKIM_KEYS_DIR" || {
        echo "Error: Failed to create DKIM keys directory" | tee -a "$ERROR_LOG"
        exit 1
    }

    # Generate DKIM key with timestamped selector
    if ! sudo opendkim-genkey -b 2048 -d "$domain" -s "$selector" -D "$DKIM_KEYS_DIR"; then
        echo "Error: Failed to generate DKIM keys" | tee -a "$ERROR_LOG"
        exit 1
    fi

    # Set proper permissions
    sudo chown -R opendkim:opendkim /etc/opendkim || {
        echo "Error: Failed to set DKIM directory permissions" | tee -a "$ERROR_LOG"
        exit 1
    }
    sudo chmod 700 "$DKIM_KEYS_DIR"

    # Configure KeyTable
    echo "$selector._domainkey.$domain $domain:$selector:$DKIM_KEYS_DIR/$selector.private" | \
        sudo tee /etc/opendkim/KeyTable >/dev/null

    # Configure SigningTable
    echo "*@$domain $selector._domainkey.$domain" | \
        sudo tee /etc/opendkim/SigningTable >/dev/null

    # Configure TrustedHosts
    echo -e "127.0.0.1\nlocalhost\n$domain" | \
        sudo tee /etc/opendkim/TrustedHosts >/dev/null

    # Create opendkim.conf with secure settings
    sudo tee /etc/opendkim.conf > /dev/null <<EOL
# Secure DKIM configuration
AutoRestart             Yes
AutoRestartRate         10/1h
UMask                   007
Syslog                  yes
SyslogSuccess           Yes
LogWhy                  Yes
Canonicalization        relaxed/relaxed
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts           refile:/etc/opendkim/TrustedHosts
KeyTable                refile:/etc/opendkim/KeyTable
SigningTable            refile:/etc/opendkim/SigningTable
Mode                    sv
PidFile                 /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                  opendkim:opendkim
Socket                  inet:8891@localhost
EOL

    # Configure Postfix to use DKIM
    sudo postconf -e "milter_default_action = accept" || {
        echo "Error: Failed to configure Postfix" | tee -a "$ERROR_LOG"
        exit 1
    }
    sudo postconf -e "milter_protocol = 6"
    sudo postconf -e "smtpd_milters = inet:localhost:8891"
    sudo postconf -e "non_smtpd_milters = inet:localhost:8891"

    # Restart services
    if ! sudo systemctl restart opendkim postfix; then
        echo "Error: Failed to restart services" | tee -a "$ERROR_LOG"
        exit 1
    fi

    # Display DNS records needed
    echo ""
    echo "===================================================================="
    echo "DKIM CONFIGURATION COMPLETE"
    echo "Add these DNS records to your domain:"
    echo ""
    echo "1. DKIM Record (TXT):"
    cat "$DKIM_KEYS_DIR/$selector.txt"
    echo ""
    echo "2. SPF Record (Recommended):"
    echo "   Name: @"
    echo "   Value: v=spf1 mx a include:$domain ~all"
    echo ""
    echo "3. DMARC Record (Recommended):"
    echo "   Name: _dmarc"
    echo "   Value: v=DMARC1; p=none; rua=mailto:admin@$domain"
    echo ""
    echo "After adding DNS records, verify with:"
    echo "  dig TXT ${selector}._domainkey.$domain +short"
    echo "  dig TXT $domain +short (for SPF)"
    echo "===================================================================="
    echo ""
}

# Configure Postfix with security best practices
configure_postfix() {
    local myhostname="$1"
    local domain="$2"

    echo "[$(date)] Configuring Postfix for $myhostname" | tee -a "$LOG_FILE"

    # Backup original config
    sudo cp /etc/postfix/main.cf /etc/postfix/main.cf.backup.$(date +%Y%m%d%H%M%S)

    # Apply secure configuration
    sudo tee /etc/postfix/main.cf > /dev/null <<EOL
# Network settings
myhostname = $myhostname
myorigin = $domain
inet_interfaces = all
mydestination = localhost

# Security settings
smtpd_banner = \$myhostname ESMTP
biff = no
append_dot_mydomain = no
readme_directory = no
disable_vrfy_command = yes
smtpd_helo_required = yes

# TLS configuration
smtp_tls_security_level = may
smtp_tls_loglevel = 1
smtpd_tls_security_level = may
smtpd_tls_loglevel = 1
smtpd_tls_cert_file=/etc/ssl/certs/ssl-cert-snakeoil.pem
smtpd_tls_key_file=/etc/ssl/private/ssl-cert-snakeoil.key

# Rate limiting
smtpd_client_message_rate_limit = 100
anvil_rate_time_unit = 60s
smtpd_client_connection_rate_limit = 10
smtpd_client_connection_count_limit = 10
smtpd_error_sleep_time = 10s

# Queue management
maximal_queue_lifetime = 1d
bounce_queue_lifetime = 1d
qmgr_message_active_limit = 1000

# Restrictions
smtpd_helo_restrictions = 
    permit_mynetworks,
    reject_invalid_helo_hostname,
    reject_non_fqdn_helo_hostname,
    permit

smtpd_sender_restrictions = 
    permit_mynetworks,
    reject_non_fqdn_sender,
    reject_unknown_sender_domain,
    permit

smtpd_recipient_restrictions =
    permit_mynetworks,
    reject_unauth_destination,
    reject_non_fqdn_recipient,
    reject_unknown_recipient_domain,
    permit

# DKIM milter configuration
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:localhost:8891
non_smtpd_milters = inet:localhost:8891
EOL

    if ! sudo postfix reload; then
        echo "Error: Failed to reload Postfix" | tee -a "$ERROR_LOG"
        exit 1
    fi
}

# Create email template with proper headers
create_email_template() {
    cat > email.html <<EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PrimeRewardSpot iPhone 16 Pro</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 600px; margin: 20px auto; padding: 20px; }
        .header { color: #0066cc; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        .footer { margin-top: 20px; font-size: 0.8em; color: #666; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="header">PrimeRewardSpot iPhone 16 Pro</h1>
        <p>Congratulations! You are eligible to win an iPhone 16 Pro.</p>
        <div class="footer">
            <p>If you wish to unsubscribe, please <a href="https://$domain/unsubscribe">click here</a>.</p>
        </div>
    </div>
</body>
</html>
EOL
}

# Create sending script with enhanced error handling
create_send_script() {
    local sender_email="$1"
    local sender_name="$2"
    local subject="$3"
    local email_list="$4"
    local domain=$(echo "$sender_email" | cut -d'@' -f2)

    cat > send.sh <<EOL
#!/bin/bash

# Enhanced Email Sending Script with Monitoring

# Initialize variables
LOG_FILE="$LOG_FILE"
ERROR_LOG="$ERROR_LOG"
EMAIL_LIST="$email_list"
SENDER_EMAIL="$sender_email"
SENDER_NAME="$sender_name"
SUBJECT="$subject"
DOMAIN="$domain"

# Initialize counters
TOTAL=\$(wc -l < "\$EMAIL_LIST")
SUCCESS=0
FAILED=0
START_TIME=\$(date +%s)

# Function to calculate time remaining
calc_time_remaining() {
    local elapsed=\$1
    local processed=\$2
    local total=\$3
    if [ \$processed -gt 0 ]; then
        local remaining=\$(( (total - processed) * elapsed / processed ))
        printf "%02d:%02d:%02d" \$((remaining/3600)) \$((remaining%3600/60)) \$((remaining%60))
    else
        echo "??:??:??"
    fi
}

# Function to validate email
validate_email() {
    local email="\$1"
    local regex="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}\$"
    [[ \$email =~ \$regex ]] && return 0 || return 1
}

# Start sending process
echo "[\$(date)] Starting email send to \$TOTAL recipients" | tee -a "\$LOG_FILE"

# Rate limiting (emails per minute)
MAX_RATE=30
SLEEP_TIME=\$((60 / MAX_RATE))

while IFS= read -r recipient; do
    # Skip empty lines
    [ -z "\$recipient" ] && continue
    
    # Validate email format
    if ! validate_email "\$recipient"; then
        echo "[\$(date)] Invalid email format: \$recipient" | tee -a "\$ERROR_LOG"
        ((FAILED++))
        continue
    fi

    # Generate Message-ID
    local message_id="<\$(date +%s%N).\$(openssl rand -hex 8)@\$DOMAIN>"

    # Send email with full headers
    if ! (
        echo "From: \$SENDER_NAME <\$SENDER_EMAIL>"
        echo "To: \$recipient"
        echo "Subject: \$SUBJECT"
        echo "Message-ID: \$message_id"
        echo "Date: \$(date -R)"
        echo "MIME-Version: 1.0"
        echo "Content-Type: text/html; charset=UTF-8"
        echo "Content-Transfer-Encoding: 7bit"
        echo "X-Mailer: Ultimate Email Script 2.1"
        echo "List-Unsubscribe: <https://\$DOMAIN/unsubscribe?email=\$recipient>"
        echo ""
        cat email.html
    ) | /usr/sbin/sendmail -t -i; then
        echo "[\$(date)] Failed to send: \$recipient" | tee -a "\$ERROR_LOG"
        ((FAILED++))
    else
        echo "[\$(date)] Sent to: \$recipient" | tee -a "\$LOG_FILE"
        ((SUCCESS++))
    fi

    # Calculate progress
    local current=\$((SUCCESS + FAILED))
    local progress=\$((current * 100 / TOTAL))
    local elapsed=\$(( \$(date +%s) - START_TIME ))
    local remaining=\$(calc_time_remaining \$elapsed \$current \$TOTAL)

    # Display progress
    printf "Progress: %d%% | Sent: %d | Failed: %d | Elapsed: %02d:%02d:%02d | Remaining: %s\\r" \\
        "\$progress" "\$SUCCESS" "\$FAILED" \\
        \$((elapsed/3600)) \$((elapsed%3600/60)) \$((elapsed%60)) \\
        "\$remaining"

    # Rate limiting
    sleep "\$SLEEP_TIME"
done < "\$EMAIL_LIST"

# Final report
echo ""
echo "[\$(date)] Email sending completed" | tee -a "\$LOG_FILE"
echo "=============================================" | tee -a "\$LOG_FILE"
echo " Total emails: \$TOTAL" | tee -a "\$LOG_FILE"
echo " Successful: \$SUCCESS" | tee -a "\$LOG_FILE"
echo " Failed: \$FAILED" | tee -a "\$LOG_FILE"
echo " Success rate: \$((SUCCESS * 100 / TOTAL))%" | tee -a "\$LOG_FILE"
echo "=============================================" | tee -a "\$LOG_FILE"

# Verify DKIM signing
if ! sudo opendkim-testkey -d "\$DOMAIN" -s "$selector" -vvv; then
    echo "WARNING: DKIM verification failed! Check your DNS records." | tee -a "\$ERROR_LOG"
fi
EOL

    chmod +x send.sh
}

# Main execution
main() {
    clear
    echo "============================================="
    echo " Ultimate Email Sending Script - Secure Setup "
    echo "============================================="
    echo ""
    echo "This script will:"
    echo "1. Install required packages"
    echo "2. Configure Postfix with security settings"
    echo "3. Set up DKIM email authentication"
    echo "4. Prepare your email campaign"
    echo ""

    # Initialize logging
    echo "[$(date)] Script started" > "$LOG_FILE"
    echo "[$(date)] Error log started" > "$ERROR_LOG"

    # Check system requirements
    check_dependencies
    check_privileges

    # Get user inputs with validation
    read -p "Enter your server's hostname (e.g., mail.example.com): " myhostname
    myhostname=${myhostname:-$(hostname)}

    while true; do
        read -p "Enter the sender email address (e.g., no-reply@example.com): " sender_email
        if validate_email "$sender_email"; then
            break
        else
            echo "Invalid email format. Please include a valid domain."
        fi
    done

    domain=$(echo "$sender_email" | cut -d'@' -f2)
    check_domain_mx "$domain"

    read -p "Enter the sender display name: " sender_name
    read -p "Enter the email subject: " subject

    while true; do
        read -p "Enter path to recipient list file: " email_list
        if [ -f "$email_list" ]; then
            # Clean up email list
            dos2unix "$email_list" 2>/dev/null
            # Remove empty lines and duplicates
            sed -i '/^$/d' "$email_list"
            awk '!seen[$0]++' "$email_list" > "${email_list}.clean" && mv "${email_list}.clean" "$email_list"
            break
        else
            echo "File not found. Please try again."
        fi
    done

    # Display configuration summary
    echo ""
    echo "Configuration Summary:"
    echo "---------------------"
    echo "Hostname: $myhostname"
    echo "Sender: $sender_name <$sender_email>"
    echo "Domain: $domain"
    echo "Subject: $subject"
    echo "Recipient list: $email_list ($(wc -l < "$email_list") addresses)"
    echo ""
    read -p "Confirm these settings? [Y/n] " -n 1 -r
    echo
    [[ $REPLY =~ ^[Nn]$ ]] && exit 0

    # Execute configuration
    install_dependencies
    configure_postfix "$myhostname" "$domain"
    configure_dkim "$domain"
    create_email_template
    create_send_script "$sender_email" "$sender_name" "$subject" "$email_list"

    # Start sending in tmux session
    echo ""
    echo "Starting email sending in detached tmux session..."
    tmux new-session -d -s email_session "./send.sh"

    echo ""
    echo "============================================="
    echo " SETUP COMPLETE!"
    echo "============================================="
    echo "Emails are being sent in the background."
    echo ""
    echo "To monitor progress:"
    echo "  tmux attach -t email_session"
    echo ""
    echo "To view logs:"
    echo "  tail -f $LOG_FILE $ERROR_LOG"
    echo ""
    echo "Remember to add the DKIM, SPF, and DMARC DNS records"
    echo "shown earlier to improve email deliverability."
    echo "============================================="
}

main