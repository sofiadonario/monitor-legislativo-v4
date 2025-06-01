/**
 * Mobile Navigation Component
 * Touch-optimized bottom navigation for mobile devices
 */

import React, { useState, useEffect, useCallback } from 'react';
import { Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  HomeIcon, 
  SearchIcon, 
  ChartBarIcon, 
  BellIcon, 
  MenuIcon,
  XIcon,
  DocumentTextIcon,
  CogIcon,
  UserIcon
} from '@heroicons/react/outline';
import { 
  HomeIcon as HomeSolid,
  SearchIcon as SearchSolid,
  ChartBarIcon as ChartSolid,
  BellIcon as BellSolid
} from '@heroicons/react/solid';
import { useSwipeable } from 'react-swipeable';
import { useLockBodyScroll, useMedia } from 'react-use';

interface NavItem {
  path: string;
  label: string;
  icon: React.ComponentType<any>;
  activeIcon: React.ComponentType<any>;
  badge?: number;
}

const navItems: NavItem[] = [
  {
    path: '/',
    label: 'Início',
    icon: HomeIcon,
    activeIcon: HomeSolid,
  },
  {
    path: '/search',
    label: 'Buscar',
    icon: SearchIcon,
    activeIcon: SearchSolid,
  },
  {
    path: '/analytics',
    label: 'Análises',
    icon: ChartBarIcon,
    activeIcon: ChartSolid,
  },
  {
    path: '/notifications',
    label: 'Alertas',
    icon: BellIcon,
    activeIcon: BellSolid,
    badge: 3,
  },
];

const menuItems = [
  {
    path: '/propositions',
    label: 'Proposições',
    icon: DocumentTextIcon,
  },
  {
    path: '/settings',
    label: 'Configurações',
    icon: CogIcon,
  },
  {
    path: '/profile',
    label: 'Perfil',
    icon: UserIcon,
  },
];

const MobileNav: React.FC = () => {
  const location = useLocation();
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [lastScrollY, setLastScrollY] = useState(0);
  const [navVisible, setNavVisible] = useState(true);
  const isMobile = useMedia('(max-width: 768px)', true);

  // Lock body scroll when menu is open
  useLockBodyScroll(isMenuOpen);

  // Hide/show nav on scroll
  useEffect(() => {
    if (!isMobile) return;

    const handleScroll = () => {
      const currentScrollY = window.scrollY;
      
      if (currentScrollY < lastScrollY || currentScrollY < 50) {
        setNavVisible(true);
      } else if (currentScrollY > lastScrollY && currentScrollY > 150) {
        setNavVisible(false);
        setIsMenuOpen(false);
      }
      
      setLastScrollY(currentScrollY);
    };

    window.addEventListener('scroll', handleScroll, { passive: true });
    
    return () => window.removeEventListener('scroll', handleScroll);
  }, [lastScrollY, isMobile]);

  // Swipe handlers
  const swipeHandlers = useSwipeable({
    onSwipedUp: () => {
      if (isMenuOpen) {
        setIsMenuOpen(false);
      }
    },
    onSwipedDown: () => {
      if (!isMenuOpen && navVisible) {
        setIsMenuOpen(true);
      }
    },
    trackMouse: false,
  });

  const handleNavClick = useCallback((path: string) => {
    setIsMenuOpen(false);
    // Haptic feedback on supported devices
    if ('vibrate' in navigator) {
      navigator.vibrate(10);
    }
  }, []);

  if (!isMobile) return null;

  return (
    <>
      {/* Bottom Navigation */}
      <AnimatePresence>
        {navVisible && (
          <motion.nav
            initial={{ y: 100 }}
            animate={{ y: 0 }}
            exit={{ y: 100 }}
            transition={{ type: 'spring', stiffness: 300, damping: 30 }}
            className="mobile-nav bg-white dark:bg-gray-900 shadow-lg border-t border-gray-200 dark:border-gray-700"
            {...swipeHandlers}
          >
            <div className="flex justify-around items-center h-full px-2">
              {navItems.map((item) => {
                const isActive = location.pathname === item.path;
                const Icon = isActive ? item.activeIcon : item.icon;

                return (
                  <Link
                    key={item.path}
                    to={item.path}
                    onClick={() => handleNavClick(item.path)}
                    className={`
                      flex flex-col items-center justify-center
                      w-full h-full py-2 px-1
                      transition-colors duration-200
                      ${isActive 
                        ? 'text-blue-600 dark:text-blue-400' 
                        : 'text-gray-600 dark:text-gray-400'
                      }
                    `}
                  >
                    <div className="relative">
                      <Icon className="w-6 h-6" />
                      {item.badge && (
                        <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full w-4 h-4 flex items-center justify-center">
                          {item.badge}
                        </span>
                      )}
                    </div>
                    <span className="text-xs mt-1">{item.label}</span>
                  </Link>
                );
              })}
              
              {/* Menu Button */}
              <button
                onClick={() => setIsMenuOpen(!isMenuOpen)}
                className="flex flex-col items-center justify-center w-full h-full py-2 px-1 text-gray-600 dark:text-gray-400"
              >
                {isMenuOpen ? (
                  <XIcon className="w-6 h-6" />
                ) : (
                  <MenuIcon className="w-6 h-6" />
                )}
                <span className="text-xs mt-1">Menu</span>
              </button>
            </div>
          </motion.nav>
        )}
      </AnimatePresence>

      {/* Slide-up Menu */}
      <AnimatePresence>
        {isMenuOpen && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setIsMenuOpen(false)}
              className="fixed inset-0 bg-black bg-opacity-50 z-40"
            />

            {/* Menu Panel */}
            <motion.div
              initial={{ y: '100%' }}
              animate={{ y: 0 }}
              exit={{ y: '100%' }}
              transition={{ type: 'spring', stiffness: 300, damping: 30 }}
              className="fixed bottom-0 left-0 right-0 bg-white dark:bg-gray-900 rounded-t-2xl shadow-xl z-50 safe-bottom"
              {...swipeHandlers}
            >
              {/* Drag Handle */}
              <div className="flex justify-center py-2">
                <div className="w-12 h-1 bg-gray-300 dark:bg-gray-700 rounded-full" />
              </div>

              {/* Menu Items */}
              <div className="px-4 pb-6">
                <h3 className="text-lg font-semibold mb-4 text-gray-900 dark:text-white">
                  Menu
                </h3>
                
                <div className="space-y-2">
                  {menuItems.map((item) => (
                    <Link
                      key={item.path}
                      to={item.path}
                      onClick={() => handleNavClick(item.path)}
                      className="flex items-center p-4 rounded-lg bg-gray-50 dark:bg-gray-800 hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
                    >
                      <item.icon className="w-6 h-6 mr-3 text-gray-600 dark:text-gray-400" />
                      <span className="text-gray-900 dark:text-white font-medium">
                        {item.label}
                      </span>
                    </Link>
                  ))}
                </div>

                {/* Quick Actions */}
                <div className="mt-6 pt-6 border-t border-gray-200 dark:border-gray-700">
                  <h4 className="text-sm font-medium text-gray-600 dark:text-gray-400 mb-3">
                    Ações Rápidas
                  </h4>
                  
                  <div className="grid grid-cols-2 gap-3">
                    <button className="p-3 rounded-lg bg-blue-50 dark:bg-blue-900/20 text-blue-600 dark:text-blue-400 font-medium">
                      Nova Busca
                    </button>
                    <button className="p-3 rounded-lg bg-green-50 dark:bg-green-900/20 text-green-600 dark:text-green-400 font-medium">
                      Criar Alerta
                    </button>
                  </div>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
};

export default MobileNav;