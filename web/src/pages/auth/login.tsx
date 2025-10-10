import { Button, Input, Card, CardBody, CardHeader, Divider } from "@heroui/react";
import axios from 'axios';
import React, { useState, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useNavigate } from 'react-router-dom';

import LocalIcon from '@/components/LocalIcon';
import api from '@/services/api';
import { toast } from '@/utils/toast';

interface OAuthProvider {
  enabled: boolean;
  name: string;
}

interface OAuthProviders {
  google?: OAuthProvider;
  github?: OAuthProvider;
  okta?: OAuthProvider;
}

export function LoginPage() {
  const { t } = useTranslation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [oauthProviders, setOAuthProviders] = useState<OAuthProviders>({});
  const navigate = useNavigate();

  const handleOAuthCallback = useCallback(() => {
    const urlParams = new window.URLSearchParams(window.location.search);
    const oauth = urlParams.get('oauth');
    
    if (oauth === 'success') {
      // Extract token from URL fragment
      const fragment = window.location.hash.substring(1);
      const fragmentParams = new window.URLSearchParams(fragment);
      const token = fragmentParams.get('token');
      const userId = fragmentParams.get('user_id');
      const username = fragmentParams.get('username');
      const role = fragmentParams.get('role');
      
      if (token && userId && username && role) {
        // Store token and redirect
        window.localStorage.setItem('token', token);
        window.localStorage.removeItem('oauth_state');
        
        toast.success(t('auth.login_success'));
        navigate('/', { replace: true });
      } else {
        toast.error(t('auth.oauth_login_failed'));
        // Clean up URL
        window.history.replaceState({}, document.title, '/login');
      }
    } else if (oauth === 'error') {
      // Handle OAuth error
      const message = urlParams.get('message') || 'unknown_error';
      window.localStorage.removeItem('oauth_state');
      
      let errorMessage = t('auth.oauth_login_failed');
      switch (message) {
        case 'oauth_not_enabled':
          errorMessage = 'OAuth is not enabled on this server';
          break;
        case 'invalid_state':
          errorMessage = 'Invalid OAuth state. Please try again.';
          break;
        case 'missing_parameters':
          errorMessage = 'Missing OAuth parameters';
          break;
        case 'token_exchange_failed':
          errorMessage = 'Failed to exchange OAuth code for token';
          break;
        case 'user_info_failed':
          errorMessage = 'Failed to get user information';
          break;
        case 'user_creation_failed':
          errorMessage = 'Failed to create or update user account';
          break;
        default:
          errorMessage = `OAuth error: ${message}`;
      }
      
      toast.error(errorMessage);
      // Clean up URL
      window.history.replaceState({}, document.title, '/login');
    }
  }, [t, navigate]);

  useEffect(() => {
    // Initialize theme on login page
    const savedTheme = window.localStorage.getItem('theme');
    if (savedTheme === 'dark') {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }

    // Check if already logged in
    const token = window.localStorage.getItem('token');
    if (token) {
      navigate('/');
    }

    // Check for OAuth callback success
    handleOAuthCallback();

    // Load available OAuth providers
    loadOAuthProviders();
  }, [navigate, handleOAuthCallback]);

  const loadOAuthProviders = async () => {
    try {
      const response = await api.get('/auth/oauth/providers');
      setOAuthProviders(response.data.providers || {});
    } catch (error) {
      console.warn('Failed to load OAuth providers:', error);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await api.post('/auth/login', { username, password });
      window.localStorage.setItem('token', response.data.token);
      toast.success(t('auth.login_success'));
      navigate('/');
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.data?.error) {
        toast.error(error.response.data.error);
      } else {
        toast.error(t('auth.login_failed'));
      }
    } finally {
      setLoading(false);
    }
  };

  const handleOAuthLogin = async (provider: 'google' | 'github' | 'okta') => {
    try {
      const response = await api.get(`/auth/oauth/${provider}/login`);
      const authUrl = response.data.auth_url;
      const state = response.data.state;

      // Store state for validation
      window.localStorage.setItem('oauth_state', state);

      // Redirect to OAuth provider
      window.location.href = authUrl;
    } catch (error) {
      if (axios.isAxiosError(error) && error.response?.data?.error) {
        toast.error(error.response.data.error);
      } else {
        toast.error(t('auth.oauth_login_failed'));
      }
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <Card className="w-full max-w-md">
        <CardHeader className="flex flex-col gap-1.5 p-6">
          <div className="flex items-center gap-2">
            <LocalIcon icon="lucide:server" className="text-primary text-2xl" />
            <h1 className="text-2xl font-bold">Unla - MCP Gateway</h1>
          </div>
          <p className="text-default-500">
            {t('auth.login_to_continue')}
          </p>
        </CardHeader>
        <CardBody className="p-6">
          <form onSubmit={handleLogin} className="flex flex-col gap-4">
            <Input
              label={t('auth.username')}
              placeholder={t('auth.username_placeholder')}
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              startContent={<LocalIcon icon="lucide:user" className="text-default-400" />}
              required
            />
            <Input
              label={t('auth.password')}
              type="password"
              placeholder={t('auth.password_placeholder')}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              startContent={<LocalIcon icon="lucide:lock" className="text-default-400" />}
              required
            />
            <Button
              type="submit"
              color="primary"
              isLoading={loading}
              className="w-full"
            >
              {t('auth.login')}
            </Button>
          </form>

          {/* OAuth Login Options */}
          {(oauthProviders.google?.enabled || oauthProviders.github?.enabled || oauthProviders.okta?.enabled) && (
            <>
              <div className="flex items-center gap-4 my-4">
                <Divider className="flex-1" />
                <span className="text-small text-default-400">
                  {t('auth.or_continue_with')}
                </span>
                <Divider className="flex-1" />
              </div>

              <div className="flex flex-col gap-3">
                {oauthProviders.google?.enabled && (
                  <Button
                    variant="flat"
                    className="group relative w-full h-12 bg-gradient-to-r from-white to-gray-50 hover:from-gray-50 hover:to-white dark:from-gray-800 dark:to-gray-750 dark:hover:from-gray-750 dark:hover:to-gray-800 border border-gray-200 dark:border-gray-600 shadow-lg hover:shadow-xl transform hover:scale-[1.02] transition-all duration-300 ease-out overflow-hidden"
                    startContent={
                      <div className="relative z-10">
                        <LocalIcon icon="simple-icons:google" className="w-5 h-5 transition-transform duration-300 group-hover:scale-110" />
                      </div>
                    }
                    onPress={() => handleOAuthLogin('google')}
                  >
                    <div className="absolute inset-0 bg-gradient-to-r from-blue-500/5 to-red-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                    <span className="relative z-10 text-gray-700 dark:text-gray-200 font-semibold transition-colors duration-300 group-hover:text-gray-900 dark:group-hover:text-white">
                      {t('auth.continue_with_google')}
                    </span>
                  </Button>
                )}

                {oauthProviders.github?.enabled && (
                  <Button
                    variant="flat"
                    className="group relative w-full h-12 bg-gradient-to-r from-white to-gray-50 hover:from-gray-50 hover:to-white dark:from-gray-800 dark:to-gray-750 dark:hover:from-gray-750 dark:hover:to-gray-800 border border-gray-200 dark:border-gray-600 shadow-lg hover:shadow-xl transform hover:scale-[1.02] transition-all duration-300 ease-out overflow-hidden"
                    startContent={
                      <div className="relative z-10">
                        <LocalIcon icon="simple-icons:github" className="w-5 h-5 text-gray-900 dark:text-gray-200 transition-transform duration-300 group-hover:scale-110" />
                      </div>
                    }
                    onPress={() => handleOAuthLogin('github')}
                  >
                    <div className="absolute inset-0 bg-gradient-to-r from-purple-500/5 to-blue-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                    <span className="relative z-10 text-gray-700 dark:text-gray-200 font-semibold transition-colors duration-300 group-hover:text-gray-900 dark:group-hover:text-white">
                      {t('auth.continue_with_github')}
                    </span>
                  </Button>
                )}

                {oauthProviders.okta?.enabled && (
                  <Button
                    variant="flat"
                    className="group relative w-full h-12 bg-gradient-to-r from-white to-gray-50 hover:from-gray-50 hover:to-white dark:from-gray-800 dark:to-gray-750 dark:hover:from-gray-750 dark:hover:to-gray-800 border border-gray-200 dark:border-gray-600 shadow-lg hover:shadow-xl transform hover:scale-[1.02] transition-all duration-300 ease-out overflow-hidden"
                    startContent={
                      <div className="relative z-10">
                        <LocalIcon icon="simple-icons:okta" className="w-5 h-5 text-blue-600 dark:text-blue-400 transition-transform duration-300 group-hover:scale-110" />
                      </div>
                    }
                    onPress={() => handleOAuthLogin('okta')}
                  >
                    <div className="absolute inset-0 bg-gradient-to-r from-blue-600/5 to-blue-400/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                    <span className="relative z-10 text-gray-700 dark:text-gray-200 font-semibold transition-colors duration-300 group-hover:text-gray-900 dark:group-hover:text-white">
                      {t('auth.continue_with_okta')}
                    </span>
                  </Button>
                )}
              </div>
            </>
          )}
        </CardBody>
      </Card>
    </div>
  );
}