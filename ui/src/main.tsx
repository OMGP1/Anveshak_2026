import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import "./styles.css";

// set the theme before the first paint so the page does not flash light
try {
  document.documentElement.dataset.theme = localStorage.getItem("theme") === "light" ? "light" : "dark";
} catch {
  document.documentElement.dataset.theme = "dark";
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
