import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { RouterProvider, createBrowserRouter } from 'react-router-dom'

import App from './App'
import './index.css'
import AuditPage from './pages/Audit'
import { ApplicationDetailPage, ApplicationsPage } from './pages/Applications'
import Dashboard from './pages/Dashboard'
import { GroupDetailPage, GroupsPage } from './pages/Groups'
import LoginsPage from './pages/Logins'
import AccessRequestsPage from './pages/AccessRequests'
import AccessRulesPage from './pages/AccessRules'
import ProvisioningPage from './pages/Provisioning'
import { UserDetailPage, UsersPage } from './pages/Users'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
})

const router = createBrowserRouter([
  {
    path: '/',
    element: <App />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'users', element: <UsersPage /> },
      { path: 'users/:userId', element: <UserDetailPage /> },
      { path: 'groups', element: <GroupsPage /> },
      { path: 'groups/:groupId', element: <GroupDetailPage /> },
      { path: 'applications', element: <ApplicationsPage /> },
      { path: 'applications/:appId', element: <ApplicationDetailPage /> },
      { path: 'logins', element: <LoginsPage /> },
      { path: 'access-rules', element: <AccessRulesPage /> },
      { path: 'access-requests', element: <AccessRequestsPage /> },
      { path: 'provisioning', element: <ProvisioningPage /> },
      { path: 'audit', element: <AuditPage /> },
      // Anything else falls back to the dashboard rather than a blank screen.
      { path: '*', element: <Dashboard /> },
    ],
  },
])

const rootElement = document.getElementById('root')
if (!rootElement) {
  throw new Error('#root is missing from index.html')
}

createRoot(rootElement).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
)
