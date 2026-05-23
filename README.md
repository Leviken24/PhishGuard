# PhishGuard: Phishing & Spam Detection System
A premium, high-performance web application designed to detect phishing URLs and spam messages using heuristic analysis and pattern matching.
## Proposed Changes
### Core Infrastructure
#### [NEW] [index.html](file:///c:/Users/bios/claude%20projects/phish-guard/index.html)
Main entry point for the application.
#### [NEW] [style.css](file:///c:/Users/bios/claude%20projects/phish-guard/style.css)
Premium CSS foundation using a dark-mode-first design system.
#### [NEW] [main.js](file:///c:/Users/bios/claude%20projects/phish-guard/main.js)
Application logic for detection algorithms and UI manipulation.
### Detection Logic
Utility functions for scanning:
- URL Pattern Matching (typosquatting, suspicious TLDs, non-ASCII chars)
- Text Heuristics (spam keywords, urgency detection, fake urgency)
## Design Aesthetics
- **Color Palette**: Cyber Black (#050505), Electric Blue (#00E5FF), Alert Red (#FF3D00).
- **Glassmorphism**: Backdrop filters for cards and input fields.
- **Animations**: CSS transitions for scan results and micro-interactions.
## Verification Plan
### Automated Tests
- Heuristic test suite for known phishing patterns.
### Manual Verification
- Testing various URLs (safe vs suspicious).
- Testing spam messages vs normal text.
