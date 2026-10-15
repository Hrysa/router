import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import '@fontsource/inter/latin-400.css';
import '@fontsource/inter/latin-500.css';
import '@fontsource/inter/latin-600.css';
import '@fontsource/inter/latin-700.css';
import './app.css';
import { App } from './App';
import { UiProvider } from './lib/ui';
import { ApiError } from './lib/api';
const client = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 5000,
      retry: (count, error) =>
        !(
          error instanceof ApiError &&
          error.status >= 400 &&
          error.status < 500
        ) && count < 1,
      refetchOnWindowFocus: true,
    },
  },
});
createRoot(document.getElementById('app')!).render(
  <StrictMode>
    <QueryClientProvider client={client}>
      <UiProvider>
        <App />
      </UiProvider>
    </QueryClientProvider>
  </StrictMode>,
);
