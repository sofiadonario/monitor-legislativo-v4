# Typo3 Integration Guide for Monitor Legislativo
## Mackintegridade Portal Integration at www.mackenzie.br

This guide provides comprehensive instructions for integrating Monitor Legislativo v4 with the Mackenzie University Typo3 CMS as part of the Mackintegridade research platform.

---

## Table of Contents
1. [Typo3 Overview](#typo3-overview)
2. [Prerequisites](#prerequisites)
3. [Backend Configuration](#backend-configuration)
4. [Page Structure Setup](#page-structure-setup)
5. [Extension Development](#extension-development)
6. [Content Elements](#content-elements)
7. [URL Routing](#url-routing)
8. [Authentication Integration](#authentication-integration)
9. [Template Customization](#template-customization)
10. [Deployment Process](#deployment-process)
11. [Troubleshooting](#troubleshooting)

---

## Typo3 Overview

Typo3 is the enterprise content management system used by Mackenzie University. For the Mackintegridade integration, we'll be working with:
- **Typo3 Version**: 11.5 LTS (or current university version)
- **Extension Framework**: Extbase/Fluid
- **Integration Type**: Embedded application with SSO

### Key Concepts
- **Pages**: Hierarchical content structure
- **TypoScript**: Configuration language
- **Fluid Templates**: Templating engine
- **Extensions**: Modular functionality additions

---

## Prerequisites

### Access Requirements
```yaml
Required Permissions:
  - Typo3 Backend Editor access
  - Mackintegridade page tree edit rights
  - Extension installation privileges (may require IT support)
  - TypoScript template modification rights
```

### Technical Requirements
- SSH access to Typo3 server (for extension deployment)
- Understanding of TypoScript basics
- Familiarity with Fluid templating
- Knowledge of Typo3 page tree structure

---

## Backend Configuration

### 1. Access Typo3 Backend
```
URL: https://www.mackenzie.br/typo3/
Username: [your_university_id]
Password: [your_password]
```

### 2. Navigate to Mackintegridade Section
```
Page Tree:
└── Root
    └── mackintegridade
        └── energia
            └── transporte (to be created)
```

### 3. Create Transport Page
```typescript
// Page properties configuration
Page Title: Monitor Legislativo de Transporte
Page Type: Standard
URL Segment: transporte
Navigation Title: Transporte
Meta Description: Monitor de legislação brasileira de transporte - Mackintegridade Energia
```

---

## Page Structure Setup

### 1. Create Page Hierarchy
```sql
-- Typo3 page structure
INSERT INTO pages (pid, title, doktype, slug) VALUES
  ((SELECT uid FROM pages WHERE slug = '/mackintegridade/energia'), 'Monitor Legislativo de Transporte', 1, 'transporte'),
  ((SELECT uid FROM pages WHERE slug = '/mackintegridade/energia/transporte'), 'Busca', 1, 'busca'),
  ((SELECT uid FROM pages WHERE slug = '/mackintegridade/energia/transporte'), 'Analytics', 1, 'analytics'),
  ((SELECT uid FROM pages WHERE slug = '/mackintegridade/energia/transporte'), 'Exportar', 1, 'exportar');
```

### 2. Page TSconfig
```typoscript
# Page TSconfig for Monitor Legislativo pages
TCEFORM.pages {
    layout.disabled = 1
    backend_layout {
        removeItems = default
        addItems {
            mackintegridade_transport = Mackintegridade Transport Layout
        }
    }
}

# RTE configuration
RTE.default.preset = mackintegridade

# Permissions
TCEMAIN.permissions {
    groupid = 15  # Mackintegridade editors group
    user = show,edit,delete,new
    group = show,edit,new
    everybody = show
}
```

---

## Extension Development

### 1. Create Monitor Legislativo Extension
```bash
# Extension structure
typo3conf/ext/monitor_legislativo/
├── Configuration/
│   ├── TCA/
│   ├── TypoScript/
│   ├── FlexForms/
│   └── Services.yaml
├── Classes/
│   ├── Controller/
│   ├── Domain/
│   └── ViewHelpers/
├── Resources/
│   ├── Private/
│   │   ├── Templates/
│   │   ├── Partials/
│   │   └── Layouts/
│   └── Public/
│       ├── Css/
│       ├── JavaScript/
│       └── Images/
├── ext_emconf.php
├── ext_localconf.php
└── ext_tables.php
```

### 2. Extension Configuration (ext_emconf.php)
```php
<?php
$EM_CONF[$_EXTKEY] = [
    'title' => 'Monitor Legislativo - Mackintegridade Transport',
    'description' => 'Legislative monitoring system for transport sector - Mackintegridade Energy Research',
    'category' => 'plugin',
    'author' => 'Mackintegridade Team',
    'author_email' => 'mackintegridade@mackenzie.br',
    'state' => 'stable',
    'version' => '1.0.0',
    'constraints' => [
        'depends' => [
            'typo3' => '11.5.0-11.5.99',
            'fluid' => '',
            'extbase' => ''
        ],
    ],
];
```

### 3. Plugin Registration (ext_localconf.php)
```php
<?php
defined('TYPO3') || die();

// Register plugin
\TYPO3\CMS\Extbase\Utility\ExtensionUtility::configurePlugin(
    'MonitorLegislativo',
    'TransportMonitor',
    [
        \Mackintegridade\MonitorLegislativo\Controller\MonitorController::class => 'index, search, analytics, export',
    ],
    // Non-cacheable actions
    [
        \Mackintegridade\MonitorLegislativo\Controller\MonitorController::class => 'search, export',
    ]
);

// Register services
\TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addService(
    'monitor_legislativo',
    'auth',
    'tx_monitorlegislativo_auth',
    [
        'title' => 'Mackintegridade SSO Authentication',
        'description' => 'Handles SSO authentication for Monitor Legislativo',
        'subtype' => '',
        'available' => true,
        'priority' => 60,
        'quality' => 80,
        'os' => '',
        'exec' => '',
        'className' => \Mackintegridade\MonitorLegislativo\Service\AuthenticationService::class,
    ]
);
```

### 4. Controller Implementation
```php
<?php
namespace Mackintegridade\MonitorLegislativo\Controller;

use TYPO3\CMS\Extbase\Mvc\Controller\ActionController;
use Psr\Http\Message\ResponseInterface;

class MonitorController extends ActionController
{
    /**
     * Main dashboard action
     */
    public function indexAction(): ResponseInterface
    {
        // Set page title
        $GLOBALS['TSFE']->page['title'] = 'Monitor Legislativo de Transporte - Mackintegridade';
        
        // Pass configuration to view
        $this->view->assignMultiple([
            'apiEndpoint' => 'https://www.mackenzie.br/mackintegridade/energia/transporte/api',
            'user' => $this->getAuthenticatedUser(),
            'config' => $this->getMackintegradeConfig()
        ]);
        
        return $this->htmlResponse();
    }
    
    /**
     * Search action
     */
    public function searchAction(string $query = ''): ResponseInterface
    {
        // Implement search logic or proxy to React app
        $this->view->assign('query', $query);
        return $this->htmlResponse();
    }
    
    /**
     * Get authenticated user from Mackintegridade SSO
     */
    protected function getAuthenticatedUser(): ?array
    {
        $authService = \TYPO3\CMS\Core\Utility\GeneralUtility::makeInstance(
            \Mackintegridade\MonitorLegislativo\Service\AuthenticationService::class
        );
        
        return $authService->getCurrentUser();
    }
    
    /**
     * Get Mackintegridade configuration
     */
    protected function getMackintegradeConfig(): array
    {
        return [
            'basePath' => '/mackintegridade/energia/transporte',
            'parentPortal' => 'https://www.mackenzie.br/mackintegridade',
            'researchArea' => 'energia',
            'projectName' => 'Monitor Legislativo de Transporte'
        ];
    }
}
```

---

## Content Elements

### 1. Create Custom Content Element
```php
// Configuration/TCA/Overrides/tt_content.php
<?php
defined('TYPO3') || die();

// Register Monitor Legislativo content element
\TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addTcaSelectItem(
    'tt_content',
    'CType',
    [
        'LLL:EXT:monitor_legislativo/Resources/Private/Language/locallang.xlf:ce.monitor',
        'monitor_legislativo',
        'content-special-html'
    ]
);

// Configure fields
$GLOBALS['TCA']['tt_content']['types']['monitor_legislativo'] = [
    'showitem' => '
        --div--;LLL:EXT:core/Resources/Private/Language/Form/locallang_tabs.xlf:general,
            --palette--;;general,
            header,
            pi_flexform,
        --div--;LLL:EXT:core/Resources/Private/Language/Form/locallang_tabs.xlf:appearance,
            --palette--;;frames,
        --div--;LLL:EXT:core/Resources/Private/Language/Form/locallang_tabs.xlf:access,
            --palette--;;hidden,
            --palette--;;access,
    ',
];

// Add FlexForm
\TYPO3\CMS\Core\Utility\ExtensionManagementUtility::addPiFlexFormValue(
    '*',
    'FILE:EXT:monitor_legislativo/Configuration/FlexForms/MonitorSettings.xml',
    'monitor_legislativo'
);
```

### 2. FlexForm Configuration
```xml
<!-- Configuration/FlexForms/MonitorSettings.xml -->
<T3DataStructure>
    <sheets>
        <sDEF>
            <ROOT>
                <TCEforms>
                    <sheetTitle>Monitor Settings</sheetTitle>
                </TCEforms>
                <type>array</type>
                <el>
                    <settings.displayMode>
                        <TCEforms>
                            <label>Display Mode</label>
                            <config>
                                <type>select</type>
                                <renderType>selectSingle</renderType>
                                <items>
                                    <numIndex index="0">
                                        <numIndex index="0">Full Dashboard</numIndex>
                                        <numIndex index="1">full</numIndex>
                                    </numIndex>
                                    <numIndex index="1">
                                        <numIndex index="0">Search Only</numIndex>
                                        <numIndex index="1">search</numIndex>
                                    </numIndex>
                                    <numIndex index="2">
                                        <numIndex index="0">Analytics Widget</numIndex>
                                        <numIndex index="1">analytics</numIndex>
                                    </numIndex>
                                </items>
                            </config>
                        </TCEforms>
                    </settings.displayMode>
                    <settings.height>
                        <TCEforms>
                            <label>Height (px)</label>
                            <config>
                                <type>input</type>
                                <size>10</size>
                                <default>800</default>
                            </config>
                        </TCEforms>
                    </settings.height>
                </el>
            </ROOT>
        </sDEF>
    </sheets>
</T3DataStructure>
```

---

## URL Routing

### 1. Site Configuration
```yaml
# config/sites/mackenzie/config.yaml
routeEnhancers:
  MonitorLegislativo:
    type: Extbase
    extension: MonitorLegislativo
    plugin: TransportMonitor
    routes:
      - routePath: '/'
        _controller: 'Monitor::index'
      - routePath: '/busca/{query}'
        _controller: 'Monitor::search'
        _arguments:
          query: query
      - routePath: '/analytics'
        _controller: 'Monitor::analytics'
      - routePath: '/exportar'
        _controller: 'Monitor::export'
    defaultController: 'Monitor::index'
    aspects:
      query:
        type: PersistedAliasMapper
        tableName: tx_monitorlegislativo_searches
        routeFieldName: slug
```

### 2. RealURL Configuration (if using older Typo3)
```php
// typo3conf/ext/realurl/Configuration/Default.php
<?php
$GLOBALS['TYPO3_CONF_VARS']['EXTCONF']['realurl']['www.mackenzie.br'] = [
    'fixedPostVars' => [
        'monitorLegislativo' => [
            [
                'GETvar' => 'tx_monitorlegislativo_monitor[action]',
                'valueMap' => [
                    'busca' => 'search',
                    'analytics' => 'analytics',
                    'exportar' => 'export'
                ],
                'noMatch' => 'bypass'
            ],
            [
                'GETvar' => 'tx_monitorlegislativo_monitor[query]',
            ]
        ],
        '123' => 'monitorLegislativo', // 123 is the page UID
    ]
];
```

---

## Authentication Integration

### 1. SSO Service Implementation
```php
<?php
namespace Mackintegridade\MonitorLegislativo\Service;

use TYPO3\CMS\Core\Authentication\AbstractAuthenticationService;
use TYPO3\CMS\Core\Database\ConnectionPool;
use TYPO3\CMS\Core\Utility\GeneralUtility;

class AuthenticationService extends AbstractAuthenticationService
{
    /**
     * Authenticate user via Mackintegridade SSO
     */
    public function authUser(array $user): int
    {
        // Check if user has Mackintegridade session
        $ssoToken = $_COOKIE['mackintegridade_sso'] ?? null;
        
        if (!$ssoToken) {
            return 100; // Continue to next service
        }
        
        // Validate token with Mackintegridade
        $validationResult = $this->validateSSOToken($ssoToken);
        
        if ($validationResult['valid']) {
            // Create or update local user
            $this->syncUser($validationResult['user']);
            return 200; // User authenticated
        }
        
        return 0; // Authentication failed
    }
    
    /**
     * Validate SSO token with Mackintegridade
     */
    protected function validateSSOToken(string $token): array
    {
        $client = GeneralUtility::makeInstance(\TYPO3\CMS\Core\Http\RequestFactory::class);
        
        try {
            $response = $client->request(
                'POST',
                'https://www.mackenzie.br/mackintegridade/auth/validate',
                [
                    'headers' => [
                        'Authorization' => 'Bearer ' . $token,
                        'X-Project' => 'energia/transporte'
                    ]
                ]
            );
            
            if ($response->getStatusCode() === 200) {
                $data = json_decode($response->getBody()->getContents(), true);
                return [
                    'valid' => true,
                    'user' => $data['user']
                ];
            }
        } catch (\Exception $e) {
            // Log error
        }
        
        return ['valid' => false];
    }
    
    /**
     * Sync user data from Mackintegridade
     */
    protected function syncUser(array $userData): void
    {
        $queryBuilder = GeneralUtility::makeInstance(ConnectionPool::class)
            ->getQueryBuilderForTable('fe_users');
        
        $existingUser = $queryBuilder
            ->select('uid')
            ->from('fe_users')
            ->where(
                $queryBuilder->expr()->eq(
                    'username',
                    $queryBuilder->createNamedParameter($userData['email'])
                )
            )
            ->executeQuery()
            ->fetchOne();
        
        $userRecord = [
            'username' => $userData['email'],
            'email' => $userData['email'],
            'name' => $userData['name'],
            'first_name' => $userData['first_name'],
            'last_name' => $userData['last_name'],
            'usergroup' => $this->getMackintegradeUserGroup($userData['roles']),
            'tx_mackintegridade_id' => $userData['id'],
            'tx_mackintegridade_research_areas' => implode(',', $userData['research_areas'] ?? [])
        ];
        
        if ($existingUser) {
            // Update existing user
            $queryBuilder
                ->update('fe_users')
                ->where(
                    $queryBuilder->expr()->eq('uid', $queryBuilder->createNamedParameter($existingUser, \PDO::PARAM_INT))
                )
                ->set('tstamp', time());
                
            foreach ($userRecord as $field => $value) {
                $queryBuilder->set($field, $value);
            }
            
            $queryBuilder->executeStatement();
        } else {
            // Create new user
            $userRecord['pid'] = $this->getMackintegradeUserPid();
            $userRecord['crdate'] = time();
            $userRecord['tstamp'] = time();
            
            $queryBuilder
                ->insert('fe_users')
                ->values($userRecord)
                ->executeStatement();
        }
    }
}
```

---

## Template Customization

### 1. Fluid Template for Monitor
```html
<!-- Resources/Private/Templates/Monitor/Index.html -->
<html xmlns:f="http://typo3.org/ns/TYPO3/CMS/Fluid/ViewHelpers"
      xmlns:ml="http://typo3.org/ns/Mackintegridade/MonitorLegislativo/ViewHelpers"
      data-namespace-typo3-fluid="true">

<f:layout name="Mackintegridade" />

<f:section name="Main">
    <div class="monitor-legislativo-container" data-api="{apiEndpoint}">
        <!-- Mackintegridade Header -->
        <ml:mackintegridade.header 
            researchArea="energia" 
            project="transporte" />
        
        <!-- Breadcrumb Navigation -->
        <nav class="mackintegridade-breadcrumb">
            <f:link.page pageUid="1">Mackintegridade</f:link.page> ›
            <f:link.page pageUid="10">Energia</f:link.page> ›
            <span>Monitor de Transporte</span>
        </nav>
        
        <!-- React App Mount Point -->
        <div id="monitor-legislativo-root" 
             data-config='{config -> f:format.json()}'
             data-user='{user -> f:format.json()}'
             style="min-height: {settings.height}px">
            <div class="loading-spinner">
                <f:translate key="loading" />
            </div>
        </div>
        
        <!-- Load React App -->
        <f:asset.script identifier="monitor-legislativo-app">
            window.MonitorLegislativoConfig = {
                apiEndpoint: '<f:format.raw>{apiEndpoint}</f:format.raw>',
                basePath: '/mackintegridade/energia/transporte',
                user: <f:format.raw>{user -> f:format.json()}</f:format.raw>
            };
        </f:asset.script>
        
        <f:asset.css identifier="monitor-legislativo-styles" 
                     href="EXT:monitor_legislativo/Resources/Public/Css/monitor.css" />
        <f:asset.script identifier="monitor-legislativo-bundle" 
                        src="https://cdn.mackintegridade.br/monitor-legislativo/bundle.js" 
                        external="1" />
    </div>
</f:section>
</html>
```

### 2. Layout Template
```html
<!-- Resources/Private/Layouts/Mackintegridade.html -->
<html xmlns:f="http://typo3.org/ns/TYPO3/CMS/Fluid/ViewHelpers"
      data-namespace-typo3-fluid="true">

<div class="mackintegridade-layout">
    <!-- Mackintegridade Global Header -->
    <f:cObject typoscriptObjectPath="lib.mackintegridade.header" />
    
    <!-- Main Content -->
    <main class="mackintegridade-content energia transporte">
        <f:render section="Main" />
    </main>
    
    <!-- Mackintegridade Global Footer -->
    <f:cObject typoscriptObjectPath="lib.mackintegridade.footer" />
</div>

<!-- Global Mackintegridade Scripts -->
<f:asset.script identifier="mackintegridade-global" 
                src="/typo3conf/ext/mackintegridade_core/Resources/Public/JavaScript/global.js" />
</html>
```

### 3. ViewHelper for Mackintegridade Components
```php
<?php
namespace Mackintegridade\MonitorLegislativo\ViewHelpers\Mackintegridade;

use TYPO3Fluid\Fluid\Core\ViewHelper\AbstractViewHelper;

class HeaderViewHelper extends AbstractViewHelper
{
    public function initializeArguments(): void
    {
        $this->registerArgument('researchArea', 'string', 'Research area identifier', true);
        $this->registerArgument('project', 'string', 'Project identifier', true);
    }
    
    public function render(): string
    {
        $researchArea = $this->arguments['researchArea'];
        $project = $this->arguments['project'];
        
        return sprintf(
            '<header class="mackintegridade-header" data-area="%s" data-project="%s">
                <div class="mackintegridade-logo">
                    <img src="/typo3conf/ext/mackintegridade_core/Resources/Public/Images/logo.svg" alt="Mackintegridade">
                </div>
                <nav class="mackintegridade-nav">
                    <a href="/mackintegridade">Home</a>
                    <a href="/mackintegridade/energia" class="active">Energia</a>
                    <a href="/mackintegridade/governanca">Governança</a>
                    <a href="/mackintegridade/transparencia">Transparência</a>
                </nav>
                <div class="project-indicator">
                    <span class="area">Energia</span>
                    <span class="separator">›</span>
                    <span class="project">Monitor de Transporte</span>
                </div>
            </header>',
            htmlspecialchars($researchArea),
            htmlspecialchars($project)
        );
    }
}
```

---

## Deployment Process

### 1. Extension Installation
```bash
# SSH to Typo3 server
ssh user@typo3.mackenzie.br

# Navigate to extensions directory
cd /var/www/typo3/typo3conf/ext/

# Clone or copy extension
git clone https://github.com/mackintegridade/monitor_legislativo.git

# Set permissions
chown -R www-data:www-data monitor_legislativo
chmod -R 755 monitor_legislativo

# Clear cache
cd /var/www/typo3
php typo3/sysext/core/bin/typo3 cache:flush
```

### 2. Database Updates
```bash
# Run database compare
php typo3/sysext/core/bin/typo3 database:updateschema

# Import initial data if needed
mysql -u typo3 -p typo3_db < monitor_legislativo/Resources/Private/Sql/initial_data.sql
```

### 3. Activate Extension
1. Login to Typo3 backend
2. Navigate to **Admin Tools > Extensions**
3. Find "Monitor Legislativo - Mackintegridade Transport"
4. Click **Activate**

### 4. Configure Extension
```typoscript
# Setup TypoScript (add to template)
plugin.tx_monitorlegislativo {
    settings {
        apiBaseUrl = https://api.mackintegridade.br/energia/transporte
        cdnUrl = https://cdn.mackintegridade.br/monitor-legislativo
        ssoEnabled = 1
        cacheLifetime = 3600
    }
    
    view {
        templateRootPaths {
            10 = EXT:monitor_legislativo/Resources/Private/Templates/
        }
        partialRootPaths {
            10 = EXT:monitor_legislativo/Resources/Private/Partials/
        }
        layoutRootPaths {
            10 = EXT:monitor_legislativo/Resources/Private/Layouts/
        }
    }
}

# Include static template
page.includeCSS {
    monitorLegislativo = EXT:monitor_legislativo/Resources/Public/Css/monitor.css
}

page.includeJSFooter {
    monitorLegislativo = EXT:monitor_legislativo/Resources/Public/JavaScript/integration.js
}
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Page Not Found (404)
```bash
# Clear all caches
php typo3/sysext/core/bin/typo3 cache:flush

# Rebuild URL cache
php typo3/sysext/core/bin/typo3 cache:warmup
```

#### 2. SSO Not Working
```php
// Check SSO configuration in LocalConfiguration.php
$GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['monitor_legislativo']['ssoEndpoint'] = 'https://www.mackenzie.br/mackintegridade/auth';
$GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['monitor_legislativo']['ssoClientId'] = 'your-client-id';
$GLOBALS['TYPO3_CONF_VARS']['EXTENSIONS']['monitor_legislativo']['ssoClientSecret'] = 'your-client-secret';
```

#### 3. React App Not Loading
```javascript
// Check browser console for errors
// Verify CDN URLs in TypoScript configuration
// Ensure CORS headers are properly set

// Debug mode
window.MonitorLegislativoDebug = true;
```

#### 4. Permission Issues
```bash
# Fix file permissions
find typo3conf/ext/monitor_legislativo -type f -exec chmod 644 {} \;
find typo3conf/ext/monitor_legislativo -type d -exec chmod 755 {} \;

# Fix ownership
chown -R www-data:www-data typo3conf/ext/monitor_legislativo
```

### Debug Mode
```typoscript
# Enable debug mode in TypoScript
plugin.tx_monitorlegislativo.settings.debug = 1

# Enable Typo3 debug mode
config.debug = 1
config.contentObjectExceptionHandler = 0
```

### Logging
```php
// Check extension logs
tail -f /var/www/typo3/var/log/typo3_monitor_legislativo.log

// Check Typo3 system log
tail -f /var/www/typo3/var/log/typo3_system.log

// Check PHP errors
tail -f /var/log/php/error.log
```

---

## Best Practices

### 1. Version Control
- Keep extension code in Git repository
- Tag releases for production deployments
- Use semantic versioning

### 2. Security
- Always escape user input in templates
- Use Typo3's QueryBuilder for database queries
- Implement proper access controls

### 3. Performance
- Enable Typo3 caching for production
- Use CDN for static assets
- Implement lazy loading for heavy components

### 4. Maintenance
- Regular Typo3 and extension updates
- Monitor error logs
- Backup before major changes

---

## Support Contacts

### Typo3 Support
- **University IT**: it-support@mackenzie.br
- **Typo3 Admin**: typo3-admin@mackenzie.br

### Mackintegridade Support
- **Portal Team**: mackintegridade-portal@mackenzie.br
- **Technical Lead**: mackintegridade-tech@mackenzie.br

### Monitor Legislativo Support
- **Development Team**: monitor-legislativo@mackenzie.br
- **Project Lead**: sofia@mackenzie.br

---

*This guide ensures seamless integration of Monitor Legislativo v4 with the Mackenzie University Typo3 CMS as part of the Mackintegridade research platform.*