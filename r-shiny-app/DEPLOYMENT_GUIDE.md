# 🚀 Academic Legislative Monitor - Deployment Guide

**Application:** R Shiny Academic Legislative Monitor  
**Data Source:** Real Brazilian Government APIs  
**Status:** ✅ Ready for Deployment

---

## 📋 Deployment Options

### 1. **Shinyapps.io** (Recommended for Academic Use)
- **Cost:** FREE (25 hours/month) or $9/month (Basic)
- **Pros:** Easy deployment, no server management, HTTPS included
- **Cons:** Limited hours on free tier
- **Best for:** Academic research, demonstrations, small teams

### 2. **Local Server** (For Institutional Use)
- **Cost:** Depends on infrastructure
- **Pros:** Full control, unlimited usage, behind firewall
- **Cons:** Requires IT support
- **Best for:** Universities, research centers

### 3. **RStudio Connect** (Enterprise)
- **Cost:** Enterprise pricing
- **Pros:** Professional features, user management
- **Cons:** Higher cost
- **Best for:** Large institutions

---

## 🔧 Pre-Deployment Setup

### **1. Install Required Software**
```bash
# Ensure R 4.3+ is installed
R --version

# Install deployment package
R -e "install.packages('rsconnect')"
```

### **2. Create Shinyapps.io Account**
1. Go to https://www.shinyapps.io/
2. Sign up for free account
3. Go to Account → Tokens
4. Copy your token for later use

### **3. Configure rsconnect**
```r
# In R, configure your account
library(rsconnect)
rsconnect::setAccountInfo(
  name = 'YOUR_ACCOUNT_NAME',
  token = 'YOUR_TOKEN',
  secret = 'YOUR_SECRET'
)
```

---

## 🚀 Deployment Process

### **Option A: Using Deployment Script (Recommended)**

```bash
# Navigate to app directory
cd academic-map-app/r-shiny-app/

# Run deployment script
R -e "source('deploy.R')"
```

The script will:
1. ✅ Check all prerequisites
2. ✅ Configure your account
3. ✅ Test locally (optional)
4. ✅ Deploy to Shinyapps.io

### **Option B: Manual Deployment**

```r
# In R, from app directory
library(rsconnect)

# Deploy the app
rsconnect::deployApp(
  appDir = ".",
  appName = "academic-legislative-monitor",
  appTitle = "Monitor Legislativo Acadêmico",
  forceUpdate = TRUE
)
```

### **Option C: RStudio IDE Deployment**

1. Open `app.R` in RStudio
2. Click "Publish" button (blue icon)
3. Select "Shinyapps.io"
4. Choose account and app name
5. Click "Publish"

---

## 🔐 Post-Deployment Configuration

### **1. Test Authentication**
```
URL: https://YOUR_ACCOUNT.shinyapps.io/academic-legislative-monitor

Test Credentials:
👨‍💼 admin / admin123
👨‍🔬 researcher / research123
👨‍🎓 student / student123
```

### **2. Configure Resource Limits**
In Shinyapps.io dashboard:
- Settings → General → Instance Size
- Settings → Advanced → Max Worker Processes
- Settings → Advanced → Connection Timeout

### **3. Monitor Usage**
- Check logs: Logs tab in dashboard
- Monitor hours: Metrics → Usage
- Set up alerts: Settings → Notifications

---

## 🏫 Institutional Deployment

### **For Universities/Research Centers**

#### **1. Shiny Server Open Source**
```bash
# Install Shiny Server
wget https://download3.rstudio.org/ubuntu-14.04/x86_64/shiny-server-1.5.20.1002-amd64.deb
sudo gdebi shiny-server-1.5.20.1002-amd64.deb

# Copy app files
sudo cp -R /path/to/r-shiny-app /srv/shiny-server/academic-legislative-monitor

# Set permissions
sudo chown -R shiny:shiny /srv/shiny-server/academic-legislative-monitor

# Restart server
sudo systemctl restart shiny-server
```

#### **2. Configure Nginx (Optional)**
```nginx
server {
    listen 80;
    server_name legislativo.universidade.br;

    location / {
        proxy_pass http://localhost:3838/academic-legislative-monitor/;
        proxy_redirect / $scheme://$http_host/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 20d;
        proxy_buffering off;
    }
}
```

#### **3. SSL Certificate**
```bash
# Using Let's Encrypt
sudo certbot --nginx -d legislativo.universidade.br
```

---

## 📊 Performance Optimization

### **1. Application Settings**
Edit `config.yml`:
```yaml
app:
  cache_duration: 24  # Increase for better performance
  max_results_per_query: 500  # Reduce for faster responses
```

### **2. Database Optimization**
```r
# In R/database.R, add connection pooling
library(pool)
pool <- dbPool(
  RSQLite::SQLite(),
  dbname = "data/legislative.db",
  minSize = 1,
  maxSize = 5
)
```

### **3. Memory Management**
For Shinyapps.io, in Settings:
- Instance Size: Medium (1GB RAM)
- Max Worker Processes: 3
- Start Count: 1

---

## 🔍 Troubleshooting

### **Common Issues**

#### **1. Package Installation Errors**
```r
# Clear package cache
remove.packages("package_name")
install.packages("package_name", dependencies = TRUE)
```

#### **2. Memory Limits**
```r
# Add to .Rprofile
options(shiny.maxRequestSize = 30*1024^2)  # 30MB
```

#### **3. API Connection Issues**
- Check internet connectivity
- Verify API status in config.yml
- Check rate limits

#### **4. Authentication Problems**
- Verify auth.R is loaded
- Check password hashing
- Review session management

### **Deployment Logs**
```r
# View deployment logs
rsconnect::showLogs(appName = "academic-legislative-monitor")
```

---

## 🔒 Security Checklist

### **Pre-Production**
- [ ] Change default passwords in `R/auth.R`
- [ ] Review API rate limits
- [ ] Set up monitoring alerts
- [ ] Test all user roles
- [ ] Verify data sanitization

### **Production**
- [ ] Use HTTPS only
- [ ] Implement session timeouts
- [ ] Regular security updates
- [ ] Monitor access logs
- [ ] Backup database regularly

---

## 📞 Support Resources

### **Technical Documentation**
- Shinyapps.io: https://docs.rstudio.com/shinyapps.io/
- Shiny Server: https://docs.rstudio.com/shiny-server/
- rsconnect: https://github.com/rstudio/rsconnect

### **Application Support**
- Check `logs/` directory
- Review `AUTHENTICATION_IMPLEMENTATION_COMPLETE.md`
- See `PRE_DEPLOYMENT_AUDIT_REPORT.md`

### **Community**
- RStudio Community: https://community.rstudio.com/
- Stack Overflow: [r] [shiny] tags

---

## ✅ Final Deployment Checklist

### **Before Deployment**
- [ ] All packages installed
- [ ] Authentication tested
- [ ] APIs responding
- [ ] Local test successful
- [ ] Backup created

### **During Deployment**
- [ ] Monitor deployment logs
- [ ] Check for errors
- [ ] Verify file uploads
- [ ] Note deployment URL

### **After Deployment**
- [ ] Test live URL
- [ ] Verify all user logins
- [ ] Check map functionality
- [ ] Test data export
- [ ] Monitor performance

---

## 🎉 Deployment Complete!

Once deployed, your Academic Legislative Monitor will be available at:

**https://YOUR_ACCOUNT.shinyapps.io/academic-legislative-monitor**

Share this URL with your academic team and start researching Brazilian legislative data!

---

**Remember:** 
- Free tier = 25 active hours/month
- Upgrade to Basic ($9/month) for 100 hours
- All government APIs are FREE
- Total cost: $0-9/month ✅