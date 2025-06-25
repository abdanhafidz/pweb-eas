# Web Programming Final Project Documentation
## Quzuu - Interactive Online Examination Platform

---

### 📋 Executive Summary

**Quzuu** is an innovative interactive online examination platform designed to revolutionize the way educational assessments are conducted. The platform addresses the growing need for diverse, engaging, and technologically advanced examination systems in modern education. By implementing a comprehensive microservice architecture and incorporating cutting-edge features like Block Code Puzzles, Quzuu provides an unparalleled examination experience that goes beyond traditional multiple-choice questions.

### 🎯 Project Overview

#### Problem Statement
Traditional online examination platforms often lack variety in question types and fail to engage students effectively, particularly in technical subjects like programming. Most existing platforms are limited to basic question formats and don't provide interactive elements that can properly assess practical skills.

#### Solution
Quzuu introduces a comprehensive examination platform featuring:
- Eight distinct question types including innovative Block Code Puzzles
- Interactive drag-and-drop programming interfaces
- Integration with automated code evaluation systems
- Modern microservice architecture for scalability
- Advanced authentication and security features

#### Key Innovation: Block Code Puzzle
The standout feature of Quzuu is the **Block Code Puzzle** system, which allows students to:
- Drag and drop code blocks to complete programs
- Fill in missing syntax through interactive typing
- Visualize program structure through block-based interfaces
- Receive real-time feedback on code construction

### 🏗️ System Architecture

#### Microservice Architecture Overview
```mermaid
graph TB
    subgraph "Frontend Service"
        FE[Next.js TypeScript<br/>Server-Side Rendering<br/>Static Generation]
    end
    subgraph "API Gateway"
        GATEWAY[Load Balancer<br/>Request Routing]
    end
    subgraph "Backend Services"
        AUTH[Authentication Service<br/>JWT & OAuth]
        EXAM[Examination Service<br/>Question Management]
        USER[User Management Service<br/>Profile & Progress]
        EVAL[Code Evaluation Service<br/>Block Code Processing]
    end
    
    subgraph "Database Layer"
        POSTGRES[(PostgreSQL<br/>Supabase)]
    end
    
    subgraph "External Services"
        MAIL[SMTP Mail Service<br/>Email Verification]
        OAUTH[Google OAuth 2.0<br/>Third-party Auth]
        JUDGE[Online Judge API<br/>Code Execution]
    end
    
    subgraph "Infrastructure"
        AWS[AWS S3<br/>Connection Pooler]
        DOCKER[Docker Containers<br/>Microservice Deployment]
    end
    

    FE --> GATEWAY
    GATEWAY --> AUTH
    GATEWAY --> EXAM
    GATEWAY --> USER
    
    AUTH --> POSTGRES
    EXAM --> POSTGRES
    USER --> POSTGRES
    EVAL --> POSTGRES
    
    AUTH --> MAIL
    AUTH --> OAUTH
    EVAL --> JUDGE
    
    POSTGRES --> AWS
    DOCKER --> AWS
```

#### Technology Stack

**Frontend Technologies:**
- **Next.js 14** with TypeScript for type safety
- **React 18** with hooks and context API
- **Tailwind CSS** for responsive design
- **React DnD** for drag-and-drop functionality
- **Axios** for HTTP client communications

**Backend Technologies:**
- **Go 1.21** with Gin framework for high performance
- **GORM** as Object-Relational Mapping tool
- **JWT-Go** for token-based authentication
- **Google OAuth 2.0** for external authentication

**Database & Storage:**
- **PostgreSQL 15** as primary database
- **Supabase** for database hosting and management
- **AWS S3** for connection pooling and file storage

### 📊 Detailed Feature Specifications

#### 1. Question Type System
```mermaid
classDiagram
    class Question {
        +ID: UUID
        +Type: QuestionType
        +Title: string
        +Description: string
        +Points: int
        +TimeLimit: duration
        +CreatedAt: timestamp
        +UpdatedAt: timestamp
        +validate()
        +render()
    }
    
    class MultipleChoice {
        +Options: []Option
        +CorrectAnswer: int
        +Randomize: bool
        +validateAnswer()
    }
    
    class ComplexMultipleChoice {
        +Options: []Option
        +CorrectAnswers: []int
        +MinSelections: int
        +MaxSelections: int
        +validateAnswer()
    }
    
    class ShortAnswer {
        +ExpectedAnswer: string
        +CaseSensitive: bool
        +AcceptedVariations: []string
        +validateAnswer()
    }
    
    class Essay {
        +MinWords: int
        +MaxWords: int
        +GradingCriteria: []Criterion
        +validateAnswer()
    }
    
    class TrueFalse {
        +CorrectAnswer: bool
        +Explanation: string
        +validateAnswer()
    }
    
    class BlockCodePuzzle {
        +CodeBlocks: []CodeBlock
        +SolutionStructure: []int
        +SyntaxRules: []Rule
        +validateStructure()
        +executeCode()
    }
    
    class BlockCodeFillIn {
        +CodeTemplate: string
        +BlankPositions: []Position
        +ExpectedAnswers: []string
        +validateCompletion()
    }
    
    class Programming {
        +ProblemStatement: string
        +TestCases: []TestCase
        +TimeLimit: duration
        +MemoryLimit: int
        +submitToJudge()
        +validateSolution()
    }
    
    Question <|-- MultipleChoice
    Question <|-- ComplexMultipleChoice
    Question <|-- ShortAnswer
    Question <|-- Essay
    Question <|-- TrueFalse
    Question <|-- BlockCodePuzzle
    Question <|-- BlockCodeFillIn
    Question <|-- Programming
```

#### 2. Block Code Puzzle Implementation
The Block Code Puzzle system represents the most innovative aspect of Quzuu:

**Technical Implementation:**
- **Drag & Drop Engine**: Built using React DnD library with custom drop zones
- **Code Block Rendering**: SVG-based visual representation of code blocks
- **Syntax Validation**: Real-time syntax checking as blocks are arranged
- **Execution Engine**: Server-side code compilation and execution for validation

**User Interaction Flow:**
```mermaid
sequenceDiagram
    participant Student
    participant Frontend
    participant BlockCodeService
    participant CodeValidator
    participant Database
    
    Student->>Frontend: Start Block Code Question
    Frontend->>BlockCodeService: Request Question Data
    BlockCodeService->>Database: Fetch Code Blocks & Template
    Database->>BlockCodeService: Return Question Data
    BlockCodeService->>Frontend: Send Structured Data
    Frontend->>Student: Render Interactive Interface
    
    loop Block Arrangement
        Student->>Frontend: Drag & Drop Code Block
        Frontend->>CodeValidator: Validate Current Structure
        CodeValidator->>Frontend: Return Validation Result
        Frontend->>Student: Visual Feedback
    end
    
    Student->>Frontend: Submit Solution
    Frontend->>BlockCodeService: Submit Block Arrangement
    BlockCodeService->>CodeValidator: Full Solution Validation
    CodeValidator->>BlockCodeService: Execution Result
    BlockCodeService->>Database: Store Result
    BlockCodeService->>Frontend: Return Grade
    Frontend->>Student: Display Result
```

### 🔐 Authentication & Security System

#### Google OAuth 2.0 Integration
Quzuu implements Google OAuth 2.0 as the primary external authentication method, providing users with a seamless login experience using their Google accounts.

```mermaid
sequenceDiagram
    participant User
    participant Frontend
    participant Backend
    participant Google OAuth
    participant Database
    
    User->>Frontend: Click "Login with Google"
    Frontend->>Google OAuth: Redirect to Google Auth
    Google OAuth->>User: Display Google Login Page
    User->>Google OAuth: Enter Google Credentials
    Google OAuth->>Frontend: Return Authorization Code
    Frontend->>Backend: Send Authorization Code
    Backend->>Google OAuth: Exchange Code for Tokens
    Google OAuth->>Backend: Return Access Token & ID Token
    Backend->>Backend: Validate & Decode ID Token
    Backend->>Database: Check/Create User Account
    Database->>Backend: User Data
    Backend->>Backend: Generate JWT Token
    Backend->>Frontend: Return JWT Token
    Frontend->>User: Login Success
```

#### Google OAuth Implementation Details
**Frontend Implementation (Next.js):**
```typescript
// Google OAuth Configuration
const googleAuth = {
  clientId: process.env.NEXT_PUBLIC_GOOGLE_CLIENT_ID,
  redirectUri: process.env.NEXT_PUBLIC_GOOGLE_REDIRECT_URI,
  scope: 'openid email profile'
};

// OAuth Login Handler
const handleGoogleLogin = async () => {
  const authUrl = `https://accounts.google.com/oauth/authorize?` +
    `client_id=${googleAuth.clientId}&` +
    `redirect_uri=${googleAuth.redirectUri}&` +
    `response_type=code&` +
    `scope=${googleAuth.scope}`;
  
  window.location.href = authUrl;
};
```

**Backend Implementation (Go):**
```go
// Google OAuth Token Exchange
func (s *AuthService) GoogleOAuthCallback(code string) (*models.User, string, error) {
    // Exchange authorization code for tokens
    token, err := s.googleOAuthConfig.Exchange(context.Background(), code)
    if err != nil {
        return nil, "", err
    }
    
    // Extract user info from ID token
    idToken := token.Extra("id_token").(string)
    claims, err := s.validateGoogleIDToken(idToken)
    if err != nil {
        return nil, "", err
    }
    
    // Create or update user account
    user, err := s.findOrCreateGoogleUser(claims)
    if err != nil {
        return nil, "", err
    }
    
    // Generate JWT token
    jwtToken, err := s.generateJWT(user)
    return user, jwtToken, err
}
```

#### Multi-layered Authentication
```mermaid
graph TB
    subgraph "Authentication Flow"
        START([User Login Request])
        VALIDATE_INPUT[Input Validation]
        CHECK_METHOD{Authentication Method}
        
        subgraph "Email Authentication"
            EMAIL_LOGIN[Email/Password Login]
            EMAIL_VERIFY[Email Verification Check]
            SEND_VERIFICATION[Send Verification Email]
            HASH_CHECK[Bcrypt Password Verification]
        end
        
        subgraph "Google OAuth Authentication"
            GOOGLE_OAUTH[Google OAuth 2.0]
            TOKEN_EXCHANGE[Exchange Auth Code for Tokens]
            TOKEN_VERIFY[Verify ID Token]
            EXTRACT_CLAIMS[Extract User Claims]
            CREATE_ACCOUNT[Create/Update User Account]
        end
        
        subgraph "JWT Token Management"
            GENERATE_JWT[Generate JWT Token]
            SET_COOKIES[Set HTTP-Only Cookies]
            STORE_SESSION[Store Session in Database]
        end
        
        SUCCESS[Authentication Success]
        FAIL[Authentication Failed]
    end
    
    START --> VALIDATE_INPUT
    VALIDATE_INPUT --> CHECK_METHOD
    
    CHECK_METHOD -->|Email| EMAIL_LOGIN
    CHECK_METHOD -->|Google| GOOGLE_OAUTH
    
    EMAIL_LOGIN --> EMAIL_VERIFY
    EMAIL_VERIFY -->|Verified| HASH_CHECK
    EMAIL_VERIFY -->|Not Verified| SEND_VERIFICATION
    HASH_CHECK -->|Valid| GENERATE_JWT
    HASH_CHECK -->|Invalid| FAIL
    SEND_VERIFICATION --> FAIL
    
    GOOGLE_OAUTH --> TOKEN_EXCHANGE
    TOKEN_EXCHANGE --> TOKEN_VERIFY
    TOKEN_VERIFY --> EXTRACT_CLAIMS
    EXTRACT_CLAIMS --> CREATE_ACCOUNT
    CREATE_ACCOUNT --> GENERATE_JWT
    
    GENERATE_JWT --> SET_COOKIES
    SET_COOKIES --> STORE_SESSION
    STORE_SESSION --> SUCCESS
```

#### Google OAuth User Data Flow
```mermaid
graph LR
    subgraph "Google OAuth Claims"
        GOOGLE_USER[Google User Data<br/>• Email<br/>• Name<br/>• Picture<br/>• Email Verified<br/>• Google ID]
    end
    
    subgraph "Backend Processing"
        VALIDATE[Validate ID Token<br/>• Signature Verification<br/>• Expiration Check<br/>• Audience Validation]
        EXTRACT[Extract Claims<br/>• Email<br/>• First Name<br/>• Last Name<br/>• Profile Picture<br/>• Google Sub ID]
        MAP[Map to User Model<br/>• Create User Entity<br/>• Set Email Verified<br/>• Link OAuth Account]
    end
    
    subgraph "Database Storage"
        USER_TABLE[(Users Table<br/>• Standard User Fields<br/>• Email Pre-verified)]
        OAUTH_TABLE[(OAuth Accounts<br/>• Provider: Google<br/>• Provider Account ID<br/>• Linked User ID)]
    end
    
    GOOGLE_USER --> VALIDATE
    VALIDATE --> EXTRACT
    EXTRACT --> MAP
    MAP --> USER_TABLE
    MAP --> OAUTH_TABLE
```

#### Security Features Implementation
1. **JWT Token System**
   - Access tokens with configurable expiration
   - Secure token storage using httpOnly cookies
   - Token validation middleware for protected routes

2. **Email Verification System**
   - SMTP integration for email delivery
   - Time-limited verification tokens
   - Account activation workflow

3. **Google OAuth 2.0 Integration**
   - Complete OAuth 2.0 flow implementation
   - ID token validation with Google's public keys
   - Automatic user account creation and linking
   - Profile data synchronization

4. **Password Security**
   - Bcrypt hashing for password storage
   - Password strength validation
   - Secure password reset functionality

### 💾 Database Design & Management

#### Entity Relationship Diagram
```mermaid
graph TB
    subgraph "USER MANAGEMENT"
        ACCOUNT["👤 ACCOUNT<br/>🔑 id (UUID)<br/>📧 username (UK)<br/>📧 email (UK)<br/>🏷️ role<br/>🔒 password<br/>✅ is_email_verified<br/>📝 is_detail_completed<br/>📅 created_at<br/>🗑️ deleted_at"]
        
        ACCOUNT_DETAILS["📋 ACCOUNT_DETAILS<br/>🔑 id (UUID)<br/>🔗 account_id (FK)<br/>👤 full_name<br/>🏫 school_name<br/>🌏 province<br/>🏙️ city<br/>🖼️ avatar<br/>📱 phone_number"]
        
        EMAIL_VERIFICATION["📧 EMAIL_VERIFICATION<br/>🔑 id (UUID)<br/>🎫 token<br/>🔗 account_id (FK)<br/>⏰ is_expired<br/>📅 created_at<br/>⏳ expired_at"]
        
        EXTERNAL_AUTH["🔗 EXTERNAL_AUTH<br/>🔑 id (UUID)<br/>🆔 oauth_id<br/>🔗 account_id (FK)<br/>🏢 oauth_provider"]
        
        FCM["📱 FCM<br/>🔑 id (UUID)<br/>🔗 account_id (FK)<br/>🔔 fcm_token"]
        
        FORGOT_PASSWORD["🔐 FORGOT_PASSWORD<br/>🔑 id (UUID)<br/>🎫 token<br/>🔗 account_id (FK)<br/>⏰ is_expired<br/>📅 created_at<br/>⏳ expired_at"]
    end
    
    subgraph "EVENT & EXAM SYSTEM"
        EVENTS["🎯 EVENTS<br/>🔑 id (UUID)<br/>📝 title<br/>🔗 slug<br/>⏰ start_event<br/>⏰ end_event<br/>🔢 event_code<br/>🌐 is_public"]
        
        ANNOUNCEMENT["📢 ANNOUNCEMENT<br/>🔑 id (UUID)<br/>📝 title<br/>📅 created_at<br/>💬 message<br/>👤 publisher<br/>🔗 event_id (FK)"]
        
        PROBLEM_SET["📚 PROBLEM_SET<br/>🔑 id (UUID)<br/>📝 title<br/>⏱️ duration<br/>🔀 randomize<br/>🔢 mc_count<br/>🔢 sa_count<br/>🔢 essay_count"]
        
        QUESTIONS["❓ QUESTIONS<br/>🔑 id (UUID)<br/>🏷️ type<br/>❓ question<br/>📋 options[]<br/>✅ ans_key[]<br/>💯 corr_mark<br/>❌ incorr_mark<br/>⭕ null_mark<br/>🔗 problem_set_id (FK)"]
        
        EVENT_ASSIGN["📝 EVENT_ASSIGN<br/>🔑 id (UUID)<br/>🔗 account_id (FK)<br/>🔗 event_id (FK)<br/>📅 assigned_at"]
        
        PROBLEM_SET_ASSIGN["🔗 PROBLEM_SET_ASSIGN<br/>🔑 id (UUID)<br/>🔗 event_id (FK)<br/>🔗 problem_set_id (FK)"]
    end
    
    subgraph "PROGRESS & RESULTS"
        EXAM_PROGRESS["📊 EXAM_PROGRESS<br/>🔑 id (UUID)<br/>🔗 account_id (FK)<br/>🔗 event_id (FK)<br/>🔗 problem_set_id (FK)<br/>📅 created_at<br/>⏰ due_at<br/>📋 questions_order[]<br/>💾 answers (JSONB)"]
        
        RESULT["🏆 RESULT<br/>🔑 id (UUID)<br/>🔗 account_id (FK)<br/>🔗 event_id (FK)<br/>🔗 problem_set_id (FK)<br/>🔗 progress_id (FK)<br/>⏰ finish_time<br/>✅ correct<br/>❌ incorrect<br/>⭕ empty<br/>🔄 on_correction<br/>📝 manual_scoring<br/>💯 mc_score<br/>📊 manual_score<br/>🎯 final_score"]
    end
    
    subgraph "LEARNING MANAGEMENT"
        ACADEMY["🎓 ACADEMY<br/>🔑 id (UUID)<br/>📝 title<br/>🔗 slug<br/>📄 description"]
        
        ACADEMY_MATERIAL["📖 ACADEMY_MATERIAL<br/>🔑 id (UUID)<br/>🔗 academy_id (FK)<br/>📝 title<br/>🔗 slug<br/>📄 description"]
        
        ACADEMY_CONTENT["📄 ACADEMY_CONTENT<br/>🔑 id (UUID)<br/>📝 title<br/>🔢 order<br/>🔗 academy_material_id (FK)<br/>📄 description"]
        
        ACADEMY_MATERIAL_PROGRESS["📈 ACADEMY_MATERIAL_PROGRESS<br/>🔑 id (UUID)<br/>🔗 account_id (FK)<br/>🔗 academy_material_id (FK)<br/>📊 progress"]
        
        ACADEMY_CONTENT_PROGRESS["📊 ACADEMY_CONTENT_PROGRESS<br/>🔑 id (UUID)<br/>🔗 account_id (FK)<br/>🔗 academy_id (FK)"]
    end
    
    subgraph "CONFIGURATION & LOCATION"
        OPTION_CATEGORY["⚙️ OPTION_CATEGORY<br/>🔑 id (UINT)<br/>📝 option_name<br/>🔗 option_slug"]
        
        OPTION_VALUES["🔧 OPTION_VALUES<br/>🔑 id (UINT)<br/>🔗 option_category_id (FK)<br/>💾 option_value"]
        
        REGION_PROVINCE["🌏 REGION_PROVINCE<br/>🔑 id (UINT)<br/>📝 name<br/>🔢 code"]
        
        REGION_CITY["🏙️ REGION_CITY<br/>🔑 id (UINT)<br/>🏷️ type<br/>📝 name<br/>🔢 code<br/>🔢 full_code<br/>🔗 province_id (FK)"]
    end
    
    %% RELATIONSHIPS
    
    %% User Management Relationships
    ACCOUNT ---|1:1| ACCOUNT_DETAILS
    ACCOUNT ---|1:M| EMAIL_VERIFICATION
    ACCOUNT ---|1:M| EXTERNAL_AUTH
    ACCOUNT ---|1:M| FCM
    ACCOUNT ---|1:M| FORGOT_PASSWORD
    
    %% Event System Relationships
    ACCOUNT ---|1:M| EVENT_ASSIGN
    EVENTS ---|1:M| EVENT_ASSIGN
    EVENTS ---|1:M| ANNOUNCEMENT
    EVENTS ---|1:M| PROBLEM_SET_ASSIGN
    PROBLEM_SET ---|1:M| PROBLEM_SET_ASSIGN
    PROBLEM_SET ---|1:M| QUESTIONS
    
    %% Progress & Results Relationships
    ACCOUNT ---|1:M| EXAM_PROGRESS
    EVENTS ---|1:M| EXAM_PROGRESS
    PROBLEM_SET ---|1:M| EXAM_PROGRESS
    EXAM_PROGRESS ---|1:1| RESULT
    ACCOUNT ---|1:M| RESULT
    EVENTS ---|1:M| RESULT
    PROBLEM_SET ---|1:M| RESULT
    
    %% Academy System Relationships
    ACADEMY ---|1:M| ACADEMY_MATERIAL
    ACADEMY_MATERIAL ---|1:M| ACADEMY_CONTENT
    ACADEMY_MATERIAL ---|1:M| ACADEMY_MATERIAL_PROGRESS
    ACADEMY ---|1:M| ACADEMY_CONTENT_PROGRESS
    ACCOUNT ---|1:M| ACADEMY_MATERIAL_PROGRESS
    ACCOUNT ---|1:M| ACADEMY_CONTENT_PROGRESS
    
    %% Configuration Relationships
    OPTION_CATEGORY ---|1:M| OPTION_VALUES
    REGION_PROVINCE ---|1:M| REGION_CITY
```

#### Database Operations & GORM Implementation

**CRUD Operations Implementation:**
```go
// User Repository Pattern
type UserRepository interface {
    Create(user *models.User) error
    GetByID(id uuid.UUID) (*models.User, error)
    GetByEmail(email string) (*models.User, error)
    Update(user *models.User) error
    Delete(id uuid.UUID) error
    List(filters map[string]interface{}) ([]*models.User, error)
}

// GORM Implementation
type userRepository struct {
    db *gorm.DB
}

func (r *userRepository) Create(user *models.User) error {
    return r.db.Create(user).Error
}

func (r *userRepository) GetByEmail(email string) (*models.User, error) {
    var user models.User
    err := r.db.Where("email = ?", email).First(&user).Error
    return &user, err
}
```

**Auto Migration System:**
```go
func AutoMigrate(db *gorm.DB) error {
    return db.AutoMigrate(
        &models.User{},
        &models.Exam{},
        &models.Question{},
        &models.ExamSession{},
        &models.QuestionResponse{},
        &models.CodeBlock{},
        &models.UserProfile{},
        &models.OAuthAccount{},
    )
}
```

### 📱 Frontend Architecture & Implementation

#### Component Architecture
```mermaid
graph TB
    subgraph "Page Components"
        HOME[Home Page]
        AUTH[Authentication Pages]
        DASHBOARD[Dashboard]
        EXAM[Exam Interface]
        RESULTS[Results Page]
    end
    
    subgraph "Layout Components"
        NAVBAR[Navigation Bar]
        SIDEBAR[Sidebar]
        FOOTER[Footer]
        LAYOUT[Main Layout]
    end
    
    subgraph "Feature Components"
        QUESTION[Question Components]
        BLOCK_CODE[Block Code Puzzle]
        TIMER[Exam Timer]
        PROGRESS[Progress Bar]
    end
    
    subgraph "UI Components"
        BUTTON[Button]
        INPUT[Input Fields]
        MODAL[Modal Dialog]
        DROPDOWN[Dropdown]
    end
    
    subgraph "Context Providers"
        AUTH_CTX[Auth Context]
        EXAM_CTX[Exam Context]
        THEME_CTX[Theme Context]
    end
    
    LAYOUT --> NAVBAR
    LAYOUT --> SIDEBAR
    LAYOUT --> FOOTER
    
    HOME --> LAYOUT
    AUTH --> LAYOUT
    DASHBOARD --> LAYOUT
    EXAM --> LAYOUT
    RESULTS --> LAYOUT
    
    EXAM --> QUESTION
    QUESTION --> BLOCK_CODE
    EXAM --> TIMER
    EXAM --> PROGRESS
    
    AUTH_CTX --> AUTH
    AUTH_CTX --> DASHBOARD
    EXAM_CTX --> EXAM
    THEME_CTX --> LAYOUT
```

#### React Context Implementation
```typescript
// Authentication Context
interface AuthContextType {
  user: User | null;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => void;
  loading: boolean;
  error: string | null;
}

export const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Exam Context
interface ExamContextType {
  currentExam: Exam | null;
  currentQuestion: Question | null;
  answers: Map<string, any>;
  timeRemaining: number;
  submitAnswer: (questionId: string, answer: any) => void;
  nextQuestion: () => void;
  previousQuestion: () => void;
  submitExam: () => Promise<void>;
}
```

### 🚀 DevOps & Deployment Strategy

#### CI/CD Pipeline Architecture
```mermaid
graph TB
    subgraph "Development Environment"
        DEV_FE[Frontend Development<br/>Next.js Local Server]
        DEV_BE[Backend Development<br/>Go Local Server]
        DEV_DB[Local PostgreSQL<br/>Development Database]
    end
    
    subgraph "Version Control"
        GITHUB[GitHub Repository<br/>Source Code Management]
        BRANCH[Feature Branches<br/>Pull Request Workflow]
    end
    
    subgraph "CI/CD Pipeline"
        GITHUB_ACTIONS[GitHub Actions<br/>Automated Workflows]
        
        subgraph "Build Stage"
            BUILD_FE[Build Frontend<br/>Next.js Production Build]
            BUILD_BE[Build Backend<br/>Go Binary Compilation]
            DOCKER_BUILD[Docker Image Build<br/>Multi-stage Dockerfile]
        end
        
        subgraph "Deploy Stage"
            DEPLOY_BE[Deploy Backend<br/>Hugging Face Spaces]
            DEPLOY_FE[Deploy Frontend<br/>Vercel Platform]
        end
    end
    
    subgraph "Production Environment"
        HF_BACKEND[Hugging Face Spaces<br/>Docker Container<br/>Go Backend Service]
        VERCEL_FRONTEND[Vercel<br/>Next.js Application<br/>Edge Deployment]
        SUPABASE_DB[Supabase PostgreSQL<br/>Production Database]
    end
    
    DEV_FE --> GITHUB
    DEV_BE --> GITHUB
    GITHUB --> BRANCH
    BRANCH --> GITHUB_ACTIONS
    
    GITHUB_ACTIONS --> BUILD_FE
    GITHUB_ACTIONS --> BUILD_BE
    BUILD_BE --> DOCKER_BUILD
    
    BUILD_FE --> DEPLOY_FE
    DOCKER_BUILD --> DEPLOY_BE
    DEPLOY_BE --> HF_BACKEND
    DEPLOY_FE --> VERCEL_FRONTEND
    
    HF_BACKEND --> SUPABASE_DB
    VERCEL_FRONTEND --> HF_BACKEND
```

#### Deployment Configuration

**Docker Configuration for Backend:**
```dockerfile
# Multi-stage Docker build
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o main ./cmd/server

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/main .
COPY --from=builder /app/configs ./configs
EXPOSE 8080
CMD ["./main"]
```

**GitHub Actions Workflow:**
```yaml
name: Deploy Quzuu Platform

on:
  push:
    branches: [ main ]

jobs:
  build-frontend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm ci
      - run: npm run build

  build-backend:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v3
        with:
          go-version: '1.21'
      - run: go mod download
      - run: go build -o main ./cmd/server

  deploy-backend:
    needs: [build-backend]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build and Push Docker to Hugging Face
        run: |
          docker build -t quzuu-backend .
          # Push repository to Hugging Face Spaces

  deploy-frontend:
    needs: [build-frontend]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Deploy to Vercel
        uses: amondnet/vercel-action@v20
        with:
          vercel-token: ${{ secrets.VERCEL_TOKEN }}
          vercel-org-id: ${{ secrets.VERCEL_ORG_ID }}
          vercel-project-id: ${{ secrets.VERCEL_PROJECT_ID }}
```

### 📊 Project Implementation Summary

#### Technical Implementation
- **Architecture**: Successfully implemented microservice architecture with Next.js frontend and Go backend
- **Database**: PostgreSQL with Supabase hosting and GORM for database operations
- **Authentication**: JWT tokens with Google OAuth 2.0 and email verification
- **Deployment**: Automated CI/CD with GitHub Actions to Hugging Face (backend) and Vercel (frontend)

#### Key Features Achieved
- **Diverse Question Types**: 8 different question formats including innovative Block Code Puzzles
- **Interactive Programming Assessment**: Drag-and-drop code block interface
- **Secure Authentication**: Multi-method login with OAuth integration
- **Automated Deployment**: Push-to-deploy workflow with Docker containerization

### 🎓 Academic Learning Outcomes

#### Web Programming Course Integration
This project successfully demonstrates the application of key web programming concepts taught in the course:

**1. Full-Stack Development**
- Frontend-backend separation with clear API boundaries
- RESTful API design principles
- Asynchronous programming patterns

**2. Database Management**
- Relational database design and normalization
- CRUD operations implementation
- ORM usage and best practices
- Database migration and version control

**3. Authentication & Authorization**
- Session management and security
- OAuth 2.0 implementation
- JWT token-based authentication
- Multi-factor authentication concepts

**4. Modern Web Technologies**
- TypeScript for type safety
- React hooks and context API
- Server-side rendering with Next.js
- Go microservice architecture

**5. DevOps & Deployment**
- Containerization with Docker
- CI/CD pipeline implementation
- Cloud platform deployment
- Automated testing and quality assurance

#### Innovation Beyond Curriculum
The Block Code Puzzle feature represents an innovative extension beyond traditional web programming coursework, demonstrating advanced user interface design and educational technology integration.

### 📈 Project Outcomes

#### Educational Learning Objectives Achieved
- **Full-Stack Development**: Complete frontend-backend integration
- **Database Management**: CRUD operations with ORM and auto-migration
- **Modern Authentication**: JWT and OAuth 2.0 implementation
- **DevOps Practices**: CI/CD pipeline with Docker containerization
- **API Development**: RESTful API design and implementation

### 📝 Conclusion

The Quzuu Interactive Online Examination Platform successfully demonstrates the practical application of web programming concepts learned throughout the course. The project integrates modern technologies including Next.js with TypeScript for the frontend, Go with Gin framework for the backend, and PostgreSQL with Supabase for data management.

Key achievements include implementing a comprehensive microservice architecture, creating an innovative Block Code Puzzle system for programming assessments, establishing secure authentication with both email verification and Google OAuth 2.0, and deploying the application using automated CI/CD pipelines with GitHub Actions.

The platform's standout Block Code Puzzle feature showcases the potential for interactive educational technology, providing students with hands-on programming assessment tools that go beyond traditional multiple-choice questions. Through its modular architecture and automated deployment system, Quzuu represents a production-ready educational platform that successfully fulfills the requirements of the web programming final project while demonstrating mastery of full-stack development principles.
