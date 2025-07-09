# 🪟 Windows Deployment Guide - Academic Legislative Monitor

## 📋 Quick Start for Windows Users

### **Option 1: Using Batch Files (Easiest)**

1. **Double-click `deploy.bat`** to start deployment
   - Or right-click → "Run as Administrator"

2. **Double-click `run_local.bat`** to test locally first

### **Option 2: Using PowerShell**

```powershell
# Method 1: Using Rscript directly
Rscript deploy.R

# Method 2: Using R in interactive mode
R
# Then in R console:
source('deploy.R')
```

### **Option 3: Using Command Prompt (cmd)**

```cmd
# Navigate to the app directory
cd "C:\Users\sofia\OneDrive\Doutorado Stuff\MackIntegridade\monitor_legislativo_v4\academic-map-app\r-shiny-app"

# Run deployment
Rscript deploy.R
```

### **Option 4: Using RStudio (Recommended)**

1. Open RStudio
2. File → Open File → Select `deploy.R`
3. Click "Source" button or press Ctrl+Shift+S
4. Follow the prompts

---

## 🔧 Troubleshooting Windows Issues

### **"R is not recognized" Error**

If you get this error, R is not in your system PATH:

1. **Find R installation:**
   - Usually in `C:\Program Files\R\R-4.x.x\bin`

2. **Add to PATH:**
   - Windows Settings → System → About → Advanced System Settings
   - Environment Variables → System Variables → Path → Edit
   - Add: `C:\Program Files\R\R-4.x.x\bin`
   - Click OK and restart PowerShell/CMD

3. **Or use full path:**
   ```powershell
   & "C:\Program Files\R\R-4.3.0\bin\Rscript.exe" deploy.R
   ```

### **PowerShell Execution Policy**

If PowerShell blocks scripts:

```powershell
# Check current policy
Get-ExecutionPolicy

# Temporarily allow scripts (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process

# Or bypass for single command
powershell -ExecutionPolicy Bypass -File "deploy.R"
```

### **Path with Spaces Issues**

Your path has spaces. In PowerShell, use quotes:

```powershell
# Change directory with quotes
cd "C:\Users\sofia\OneDrive\Doutorado Stuff\MackIntegridade\monitor_legislativo_v4\academic-map-app\r-shiny-app"

# Or use single quotes
cd 'C:\Users\sofia\OneDrive\Doutorado Stuff\MackIntegridade\monitor_legislativo_v4\academic-map-app\r-shiny-app'
```

---

## 🚀 Step-by-Step Deployment (Windows)

### **1. Test Locally First**

```powershell
# In PowerShell or CMD
Rscript run_local.R

# Or double-click run_local.bat
```

### **2. Install rsconnect Package**

```r
# In R or RStudio
install.packages("rsconnect")
```

### **3. Get Shinyapps.io Token**

1. Go to https://www.shinyapps.io/
2. Sign up for free account
3. Click on your name → Tokens
4. Copy the token command

### **4. Configure Account**

```r
# In R console
library(rsconnect)
rsconnect::setAccountInfo(
  name = 'your-account-name',
  token = 'your-token-here',
  secret = 'your-secret-here'
)
```

### **5. Deploy Application**

```powershell
# Run deployment script
Rscript deploy.R

# Or in RStudio
source('deploy.R')
```

---

## 📱 Alternative: Deploy from RStudio

### **Easiest Method for Windows Users:**

1. **Open RStudio**
2. **File → Open Project** (if you have .Rproj) or **File → Open File → app.R**
3. **Click "Publish" button** (blue icon in top-right of editor)
4. **Select "Publish Application"**
5. **Choose "Shinyapps.io"**
6. **Follow the wizard**

---

## 🆘 Common Windows-Specific Issues

### **Issue 1: OneDrive Sync Problems**

OneDrive might cause issues. Solutions:
- Pause OneDrive sync during deployment
- Copy project to a non-OneDrive location:
  ```powershell
  xcopy /E /I "." "C:\temp\r-shiny-app"
  cd "C:\temp\r-shiny-app"
  Rscript deploy.R
  ```

### **Issue 2: Antivirus Blocking**

Windows Defender might block R scripts:
- Add R installation folder to exclusions
- Temporarily disable real-time protection
- Run as Administrator

### **Issue 3: Package Installation Fails**

```r
# Try different CRAN mirror
options(repos = c(CRAN = "https://cran.microsoft.com/"))

# Or manually select mirror
chooseCRANmirror()

# Install with dependencies
install.packages("rsconnect", dependencies = TRUE)
```

---

## ✅ Quick Commands Reference

### **PowerShell Commands:**
```powershell
# Test locally
Rscript run_local.R

# Deploy to production
Rscript deploy.R

# Open R console
R

# Check R version
R --version
```

### **In R Console:**
```r
# Source deployment script
source('deploy.R')

# Manual deployment
library(rsconnect)
deployApp()

# Check logs
showLogs()
```

---

## 🎯 Success Indicators

You'll know deployment succeeded when:
1. ✅ No error messages in console
2. ✅ Browser opens with your app URL
3. ✅ You can login with test credentials
4. ✅ Map loads with Brazilian states
5. ✅ Data filters work properly

---

## 📞 Windows-Specific Help

### **R Installation Help:**
- Download R: https://cran.r-project.org/bin/windows/base/
- Download RStudio: https://www.rstudio.com/products/rstudio/download/

### **Path Issues:**
- Use forward slashes: `C:/Users/sofia/...`
- Or escape backslashes: `C:\\Users\\sofia\\...`
- Or use raw strings: `r"(C:\Users\sofia\...)"`

### **Still Having Issues?**

Try the simplest approach:
1. Open RStudio
2. Open `app.R`
3. Click "Run App" button to test
4. Click "Publish" button to deploy

This avoids all command-line issues!

---

**Remember:** The easiest way on Windows is to use RStudio's GUI for deployment rather than command line!