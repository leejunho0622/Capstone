import { lazy, Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { Spinner } from "./components/ui";
import { SettingsProvider } from "./store/settings";
import { LiveDataProvider } from "./store/liveData";
import { TriageProvider } from "./store/triage";
import { UiProvider } from "./store/ui";

// 페이지별 코드 분할 (첫 화면 로딩을 가볍게)
const OverviewPage = lazy(() => import("./pages/OverviewPage"));
const AlertsPage = lazy(() => import("./pages/AlertsPage"));
const TrafficPage = lazy(() => import("./pages/TrafficPage"));
const ChainsPage = lazy(() => import("./pages/ChainsPage"));
const AiQualityPage = lazy(() => import("./pages/AiQualityPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const DetailPage = lazy(() => import("./pages/DetailPage"));

function PageFallback() {
  return (
    <div className="flex h-64 items-center justify-center">
      <Spinner size={20} />
    </div>
  );
}

export default function App() {
  return (
    <SettingsProvider>
      <UiProvider>
        <LiveDataProvider>
          <TriageProvider>
            <Routes>
              <Route element={<AppShell />}>
                <Route
                  index
                  element={
                    <Suspense fallback={<PageFallback />}>
                      <OverviewPage />
                    </Suspense>
                  }
                />
                <Route
                  path="alerts"
                  element={
                    <Suspense fallback={<PageFallback />}>
                      <AlertsPage />
                    </Suspense>
                  }
                />
                <Route
                  path="traffic"
                  element={
                    <Suspense fallback={<PageFallback />}>
                      <TrafficPage />
                    </Suspense>
                  }
                />
                <Route
                  path="chains"
                  element={
                    <Suspense fallback={<PageFallback />}>
                      <ChainsPage />
                    </Suspense>
                  }
                />
                <Route
                  path="ai"
                  element={
                    <Suspense fallback={<PageFallback />}>
                      <AiQualityPage />
                    </Suspense>
                  }
                />
                <Route
                  path="settings"
                  element={
                    <Suspense fallback={<PageFallback />}>
                      <SettingsPage />
                    </Suspense>
                  }
                />
                <Route
                  path="incidents/:id"
                  element={
                    <Suspense fallback={<PageFallback />}>
                      <DetailPage kind="incident" />
                    </Suspense>
                  }
                />
                <Route
                  path="flows/:id"
                  element={
                    <Suspense fallback={<PageFallback />}>
                      <DetailPage kind="flow" />
                    </Suspense>
                  }
                />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Route>
            </Routes>
          </TriageProvider>
        </LiveDataProvider>
      </UiProvider>
    </SettingsProvider>
  );
}
