# Web Programming Final Project Documentation
- Muhammad Rasyad Lubis (5054231 010)
- Faiz Muhammad Kautsar (5054231 013)
- Shalahuddin Ahmad Cahyoga (5054231 014)
- Abdan Hafidz (5054231 021)
## Quzuu - Interactive Online Examination Platform

[Demonstration Video](https://youtu.be/_XGXD4BqFT4) <br />
[Paper File](https://github.com/abdanhafidz/pweb-eas/blob/main/Laporan%20PWeb%20EAS%20-%20Kelompok%20Dalam.pdf) <br />
[Slides/PPT](https://www.canva.com/design/DAGrXqPwz9k/ce2cz7WtK94LfV6by9b9nA/view?utm_content=DAGrXqPwz9k&utm_campaign=designshare&utm_medium=link2&utm_source=uniquelinks&utlId=hb39ba8e556) <br />
[Front-End Link : quzuu.vercel.app](https://quzuu.vercel.app) <br />
[Backend API Gateway : lifedebugger-quzuu-api-dev.hf.space](https://lifedebugger-quzuu-api-dev.hf.space/) <br />
[Postman Documentation](https://documenter.getpostman.com/view/13117366/2sB2ixitUr) <br />


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
- **Drag & Drop Engine**: Built using native React useState for click, drag and drop features
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
package services

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"godp.abdanhafidz.com/models"
	"godp.abdanhafidz.com/repositories"
	"google.golang.org/api/idtoken"
)

type GoogleAuthService struct {
	Service[models.ExternalAuth, models.AuthenticatedUser]
}

func (s *GoogleAuthService) Authenticate(isAgree bool) {
	GoogleAuth := repositories.GetExternalAccountByOauthId(s.Constructor.OauthID)
	payload, errGoogleAuth := idtoken.Validate(context.Background(), s.Constructor.OauthID, "")
	s.Error = errGoogleAuth
	if errGoogleAuth != nil {
		s.Exception.Unauthorized = true
		s.Exception.Message = "Oauth Provider Failed Login (Google Authentication)"
		return
	}
	email := payload.Claims["email"]
	checkRegisteredEmail := repositories.GetAccountbyEmail(email.(string))
	if !checkRegisteredEmail.NoRecord {
		token, _ := GenerateToken(&checkRegisteredEmail.Result)
		checkRegisteredEmail.Result.Password = "SECRET"
		s.Result = models.AuthenticatedUser{
			Account: checkRegisteredEmail.Result,
			Token:   token,
		}
		return
	}
	if GoogleAuth.NoRecord {
		if !isAgree {
			s.Exception.BadRequest = true
			s.Exception.Message = "Please agree to the terms and conditions to create an account"
			return
		}
		s.Constructor.OauthProvider = "Google"

		createAccount := repositories.CreateAccount(models.Account{
			Id:              uuid.New(),
			Username:        payload.Claims["name"].(string),
			Email:           email.(string),
			IsEmailVerified: true,
		})

		s.Constructor.AccountId = createAccount.Result.Id
		createGoogleAuth := repositories.CreateExternalAuth(s.Constructor)

		GoogleAuth.Result.AccountId = createGoogleAuth.Result.AccountId
		userProfile := UserProfileService{}
		userProfile.Constructor.AccountId = GoogleAuth.Result.AccountId
		userProfile.Create()
		if userProfile.Error != nil {
			s.Error = userProfile.Error
			return
		}
		s.Error = createGoogleAuth.RowsError
		s.Error = errors.Join(s.Error, createAccount.RowsError)
	}

	accountData := repositories.GetAccountById(GoogleAuth.Result.AccountId)
	token, err_tok := GenerateToken(&accountData.Result)

	if err_tok != nil {
		s.Error = errors.Join(s.Error, err_tok)
	}

	accountData.Result.Password = "SECRET"
	s.Result = models.AuthenticatedUser{
		Account: accountData.Result,
		Token:   token,
	}
	s.Error = accountData.RowsError

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
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbUser := os.Getenv("DB_USER")
	dbPassword := os.Getenv("DB_PASSWORD")
	dbName := os.Getenv("DB_NAME")
	Salt := os.Getenv("SALT")
	dsn := "host=" + dbHost + " user=" + dbUser + " password=" + dbPassword + " dbname=" + dbName + " port=" + dbPort + " sslmode=disable TimeZone=Asia/Jakarta"
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{TranslateError: true})

```
```go

package repositories

import (
	"fmt"
	"godp.abdanhafidz.com/config"
	"gorm.io/gorm"
	"strings"
)

type Repositories interface {
	FindAllPaginate()
	Where()
	Find()
	Create()
	Update()
	CustomQuery()
	Delete()
}
type PaginationConstructor struct {
	Limit    int
	Offset   int
	Filter   string
	FilterBy string
}

type PaginationMetadata struct {
	TotalRecords int `json:"total_records"`
	TotalPages   int `json:"total_pages"`
	CurrentPage  int `json:"current_page"`
	PageSize     int `json:"page_size"`
}

type CustomQueryConstructor struct {
	SQL    string
	Values interface{}
}

type Repository[TConstructor any, TResult any] struct {
	Constructor TConstructor
	Pagination  PaginationConstructor
	CustomQuery CustomQueryConstructor
	Result      TResult
	Transaction *gorm.DB
	RowsCount   int
	NoRecord    bool
	RowsError   error
}

func Construct[TConstructor any, TResult any](constructor ...TConstructor) *Repository[TConstructor, TResult] {
	if len(constructor) == 1 {
		return &Repository[TConstructor, TResult]{
			Constructor: constructor[0],
			Transaction: config.DB,
		}
	}
	return &Repository[TConstructor, TResult]{
		Constructor: constructor[0],
		Transaction: config.DB.Begin(),
	}
}
func (repo *Repository[T1, T2]) Transactions(transactions ...func(*Repository[T1, T2]) *gorm.DB) {
	for _, tx := range transactions {
		repo.Transaction = tx(repo)
		if repo.RowsError != nil {
			return
		}
	}
}
func WhereGivenConstructor[T1 any, T2 any](repo *Repository[T1, T2]) *gorm.DB {
	tx := repo.Transaction.Where(&repo.Constructor)
	repo.RowsCount = int(tx.RowsAffected)
	repo.NoRecord = repo.RowsCount == 0
	repo.RowsError = tx.Error
	return tx
}
func Find[T1 any, T2 any](repo *Repository[T1, T2]) *gorm.DB {
	tx := repo.Transaction.Find(&repo.Result)
	repo.RowsCount = int(tx.RowsAffected)
	repo.NoRecord = repo.RowsCount == 0
	repo.RowsError = tx.Error
	return tx
}

func FindAllPaginate[T1 any, T2 any](repo *Repository[T1, T2]) *gorm.DB {
	tx := repo.Transaction.Limit(repo.Pagination.Limit).Offset(repo.Pagination.Offset)

	tx = buildFilter(tx, repo.Pagination)

	tx = tx.Find(&repo.Result)

	repo.RowsCount = int(tx.RowsAffected)
	repo.NoRecord = repo.RowsCount == 0
	repo.RowsError = tx.Error

	return tx
}

func Create[T1 any](repo *Repository[T1, T1]) *gorm.DB {
	tx := repo.Transaction.Create(&repo.Constructor)
	repo.RowsCount = int(tx.RowsAffected)
	repo.NoRecord = repo.RowsCount == 0
	repo.RowsError = tx.Error
	repo.Result = repo.Constructor
	return tx
}

func Update[T1 any](repo *Repository[T1, T1]) *gorm.DB {
	tx := repo.Transaction.Save(&repo.Constructor)
	repo.RowsCount = int(tx.RowsAffected)
	repo.NoRecord = repo.RowsCount == 0
	repo.RowsError = tx.Error
	repo.Result = repo.Constructor
	return tx
}

func Delete[T1 any](repo *Repository[T1, T1]) *gorm.DB {
	tx := repo.Transaction.Delete(&repo.Constructor)
	repo.RowsCount = int(tx.RowsAffected)
	repo.NoRecord = repo.RowsCount == 0
	repo.RowsError = tx.Error
	return tx
}

func CustomQuery[T1 any, T2 any](repo *Repository[T1, T2]) *gorm.DB {
	tx := repo.Transaction.Raw(repo.CustomQuery.SQL, repo.CustomQuery.Values).Scan(&repo.Result)
	repo.RowsCount = int(tx.RowsAffected)
	repo.NoRecord = repo.RowsCount == 0
	repo.RowsError = tx.Error
	return tx
}

func buildFilter(db *gorm.DB, pagination PaginationConstructor) *gorm.DB {
	if pagination.Filter != "" && pagination.FilterBy != "" {
		filterFields := strings.Split(pagination.FilterBy, ",")
		filterValues := strings.Split(pagination.Filter, ",")

		for i, field := range filterFields {
			if i >= len(filterValues) {
				break
			}
			filterValue := filterValues[i]
			if filterValue != "" {
				condition := fmt.Sprintf("%s ILIKE ?", field)
				db = db.Where(condition, "%"+filterValue+"%")
			}
		}
	}
	return db
}
```

**Auto Migration System:**
```go
	db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\";")
	if err := db.AutoMigrate(&models.Account{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.AccountDetails{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.EmailVerification{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.ExternalAuth{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.FCM{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.ForgotPassword{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Events{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Announcement{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.ProblemSet{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Questions{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.EventAssign{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.ProblemSetAssign{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.ExamProgress{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.ExamProgress_Result{}); err != nil {
		log.Fatal(err)
	}
	if err := db.AutoMigrate(&models.Result{}); err != nil {
		log.Fatal(err)
	}
```

### 📱 Frontend Architecture & Implementation

#### Component Architecture
```mermaid
graph TB
    subgraph "Authentication System"
        LOGIN[Login Page]
        REGISTER[Register Page]
        VERIFY[Verify Email Page]
        RESET[Reset Password Page]
        COMPLETE[Complete Profile Page]
        GOOGLE_AUTH[Google OAuth]
    end
    
    subgraph "Main Pages"
        HOME[Home Page]
        EVENT_LIST[Event List]
        EVENT_DETAILS[Event Details]
        QUIZ_START[Quiz Start]
        QUIZ_PAGE[Quiz Interface]
        LEADERBOARD[Leaderboard]
        ANNOUNCEMENT[Announcement]
        SCOREBOARD[Scoreboard]
    end
    
    subgraph "Layout & Navigation"
        NAVBAR[Navbar Component]
        USER_DROPDOWN[User Dropdown]
        NAV_EVENT[Event Navigation]
        NAV_QUIZ[Quiz Navigation]
        PROVIDERS[Context Providers]
    end
    
    subgraph "Question Types"
        RADIO[Radio Answer]
        CHECKBOX[Checkbox Answer]
        SHORT[Short Answer]
        CODE_SHORT[Code Short Answer]
        CLICK_CHIP[Click Chip Answer]
        FILE[File Answer]
        TRUE_FALSE[True/False Answer]
        CODE_EDITOR[Code Editor Answer]
    end
    
    subgraph "UI Components (shadcn/ui)"
        BUTTON[Button]
        INPUT[Input]
        FORM[Form Components]
        TABLE[Table Components]
        SELECT[Select]
        LABEL[Label]
        TOAST[Toast Notifications]
        RADIO_GROUP[Radio Group]
    end
    
    subgraph "Specialized Components"
        COUNTDOWN[Countdown Timer]
        QUIZ_CONTAINER[Quiz Container]
        SECTION_QUIZ[Section Quiz]
        DATA_TABLE[Data Table]
        DRAGGABLE[Draggable Answer]
    end
    
    subgraph "Context & State Management"
        AUTH_CONTEXT[Auth Context]
        NEXTAUTH[NextAuth Session]
        API_CLIENT[API Client]
    end
    
    subgraph "External Services"
        BACKEND_API[Backend API]
        GOOGLE_OAUTH[Google OAuth Provider]
    end
    
    %% Main Flow Connections
    HOME --> EVENT_LIST
    EVENT_LIST --> EVENT_DETAILS
    EVENT_DETAILS --> QUIZ_START
    QUIZ_START --> QUIZ_PAGE
    
    %% Authentication Flow
    LOGIN --> GOOGLE_AUTH
    REGISTER --> VERIFY
    VERIFY --> COMPLETE
    COMPLETE --> HOME
    
    %% Layout Connections
    NAVBAR --> USER_DROPDOWN
    PROVIDERS --> AUTH_CONTEXT
    PROVIDERS --> NEXTAUTH
    
    %% Quiz System
    QUIZ_PAGE --> QUIZ_CONTAINER
    QUIZ_CONTAINER --> RADIO
    QUIZ_CONTAINER --> CHECKBOX
    QUIZ_CONTAINER --> SHORT
    QUIZ_CONTAINER --> CODE_SHORT
    QUIZ_CONTAINER --> CLICK_CHIP
    QUIZ_CONTAINER --> FILE
    QUIZ_CONTAINER --> TRUE_FALSE
    QUIZ_CONTAINER --> CODE_EDITOR
    
    QUIZ_PAGE --> NAV_QUIZ
    NAV_QUIZ --> COUNTDOWN
    
    %% Data Management
    AUTH_CONTEXT --> API_CLIENT
    API_CLIENT --> BACKEND_API
    NEXTAUTH --> GOOGLE_OAUTH
    
    %% UI Component Usage
    QUIZ_CONTAINER --> BUTTON
    QUIZ_CONTAINER --> INPUT
    AUTH --> FORM
    HOME --> DATA_TABLE
    
    %% Specialized Features
    EVENT_DETAILS --> SECTION_QUIZ
    QUIZ_PAGE --> COUNTDOWN
    HOME --> DATA_TABLE
    
    %% Notifications
    API_CLIENT --> TOAST
    AUTH_CONTEXT --> TOAST
    
    style AUTH_CONTEXT fill:#e1f5fe
    style NEXTAUTH fill:#e8f5e8
    style BACKEND_API fill:#fff3e0
    style QUIZ_CONTAINER fill:#f3e5f5
    style HOME fill:#e8eaf6
```

#### React Context Implementation
```typescript
// Authentication Context
"use client"

import React, {
    createContext,
    useContext,
    useState,
    useEffect,
    ReactNode,
} from "react"
import { useRouter, usePathname } from "next/navigation"
import { useSession } from "next-auth/react"
import { getAuthToken, removeAuthToken, syncNextAuthSession } from "@/lib/api"
import { toast } from "@/hooks/use-toast"
import Cookies from "js-cookie"

interface UserData {
    id?: string
    username: string
    email: string
    avatar?: string
    fullName?: string
    schoolName?: string
    province?: string
    city?: string
    phoneNumber?: string
    isEmailVerified: boolean
    isProfileComplete: boolean
}

interface AuthContextType {
    user: UserData | null
    isLoading: boolean
    isAuthenticated: boolean
    logout: () => Promise<void>
    refreshUserData: () => Promise<void>
    setEmailVerified: (value: boolean) => void
    setProfileComplete: (value: boolean) => void
}

const defaultAuthContext: AuthContextType = {
    user: null,
    isLoading: true,
    isAuthenticated: false,
    logout: async () => {},
    refreshUserData: async () => {},
    setEmailVerified: () => {},
    setProfileComplete: () => {},
}

export const AuthContext = createContext<AuthContextType>(defaultAuthContext)

export const useAuth = () => useContext(AuthContext)

export const AuthProvider = ({ children }: { children: ReactNode }) => {
    const [user, setUser] = useState<UserData | null>(null)
    const [isLoading, setIsLoading] = useState(true)
    const [isAuthenticated, setIsAuthenticated] = useState(false)
    const [initializationComplete, setInitializationComplete] = useState(false)
    
    const router = useRouter()
    const pathname = usePathname()
    
    // Get NextAuth session
    const { data: session, status: sessionStatus } = useSession()

    console.log("🔍 AuthContext Debug:", {
        sessionStatus,
        hasSession: !!session,
        hasBackendToken: !!session?.backendToken,
        isLoading,
        initializationComplete,
        isAuthenticated,
        userEmail: user?.email
    })

    const setEmailVerified = (value: boolean) => {
        if (user) {
            setUser({
                ...user,
                isEmailVerified: value,
            })
        }
    }

    const setProfileComplete = (value: boolean) => {
        console.log("🔄 Setting profile complete to:", value)
        if (user) {
            const updatedUser = {
                ...user,
                isProfileComplete: value,
            }
            setUser(updatedUser)
            console.log("✅ User updated in context:", updatedUser)
        } else {
            console.warn("⚠️ No user found when trying to set profile complete")
        }
    }

    // Function to parse JWT and extract data
    const parseJwt = (token: string) => {
        try {
            const base64Url = token.split(".")[1]
            const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/")
            const jsonPayload = decodeURIComponent(
                atob(base64)
                    .split("")
                    .map((c) => {
                        return (
                            "%" +
                            ("00" + c.charCodeAt(0).toString(16)).slice(-2)
                        )
                    })
                    .join(""),
            )

            return JSON.parse(jsonPayload)
        } catch (e) {
            console.error("Error parsing JWT:", e)
            return null
        }
    }

    // Handle OAuth session (NextAuth)
    const handleOAuthSession = async (session: any) => {
        if (!session?.backendToken) return false

        try {
            console.log("🔄 Processing OAuth session...")
            
            const accountData = await syncNextAuthSession(session)
            
            if (accountData) {
                console.log("✅ OAuth session processed successfully")
                
                // Check localStorage for manual profile completion flag
                const manualProfileComplete = localStorage.getItem("profile_completed") === "true"
                const backendProfileComplete = accountData.is_detail_completed || false
                
                // Use manual flag if backend hasn't been updated yet
                const finalProfileComplete = manualProfileComplete || backendProfileComplete
                
                console.log("🔍 Profile complete status:", {
                    backend: backendProfileComplete,
                    manual: manualProfileComplete,
                    final: finalProfileComplete
                })
                
                setUser({
                    id: accountData.id,
                    username: accountData.username || session.user?.name || "User",
                    email: accountData.email || session.user?.email || "",
                    avatar: session.user?.image,
                    fullName: session.user?.name,
                    isEmailVerified: accountData.is_email_verified || false,
                    isProfileComplete: finalProfileComplete,
                })
                
                setIsAuthenticated(true)
                return true
            }
        } catch (error) {
            console.error("❌ Failed to process OAuth session:", error)
        }
        
        return false
    }

    // Handle regular authentication (email/password)
    const handleRegularAuth = async () => {
        const token = getAuthToken()
        
        if (!token) {
            console.log("❌ No auth token found")
            setUser(null)
            setIsAuthenticated(false)
            return false
        }

        try {
            console.log("🔄 Processing regular authentication...")
            
            // Verify token before making API call
            const tokenData = parseJwt(token)
            const currentTime = Math.floor(Date.now() / 1000)

            if (tokenData && tokenData.exp && tokenData.exp < currentTime) {
                console.log("⏰ Token expired")
                throw new Error("Token expired")
            }

            // Make API call with valid token
            const response = await fetch(
                `${process.env.NEXT_PUBLIC_API_BASE_URL}/user/me`,
                {
                    method: "GET",
                    headers: {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + token,
                    },
                },
            )

            if (!response.ok) {
                throw new Error(`API error: ${response.status}`)
            }

            const userData = await response.json()

            if (userData && userData.data && userData.data.account) {
                const account = userData.data.account
                const details = userData.data.details || {}

                console.log("✅ Regular auth processed successfully")

                setUser({
                    id: account.id,
                    username: account.username,
                    email: account.email,
                    avatar: details.avatar,
                    fullName: details.full_name,
                    schoolName: details.school_name,
                    province: details.province,
                    city: details.city,
                    phoneNumber: details.phone_number,
                    isEmailVerified: account.is_email_verified || false,
                    isProfileComplete: account.is_detail_completed || false,
                })

                setIsAuthenticated(true)
                return true
            }
        } catch (error) {
            console.error("❌ Regular auth failed:", error)
            
            if (
                error instanceof Error &&
                (error.message.includes("Token expired") ||
                    error.message.includes("API error: 401"))
            ) {
                // Clear expired token
                removeAuthToken()
                setUser(null)
                setIsAuthenticated(false)
            }
        }
        
        return false
    }

    // Main initialization effect
    useEffect(() => {
        const initializeAuth = async () => {
            console.log("🚀 Initializing authentication...")
            
            // Wait for NextAuth to be ready
            if (sessionStatus === "loading") {
                console.log("⏳ Waiting for NextAuth...")
                return
            }

            setIsLoading(true)
            
            try {
                let authSuccess = false

                // Try OAuth first if available
                if (session?.backendToken) {
                    authSuccess = await handleOAuthSession(session)
                }

                // Fall back to regular auth if OAuth not available or failed
                if (!authSuccess) {
                    authSuccess = await handleRegularAuth()
                }

                // If no authentication method worked
                if (!authSuccess) {
                    console.log("❌ No valid authentication found")
                    setUser(null)
                    setIsAuthenticated(false)
                }

            } catch (error) {
                console.error("❌ Auth initialization failed:", error)
                setUser(null)
                setIsAuthenticated(false)
            } finally {
                setIsLoading(false)
                setInitializationComplete(true)
                console.log("✅ Auth initialization complete")
            }
        }

        initializeAuth()
    }, [session, sessionStatus])

    // Refreshable auth function
    const refreshUserData = async (): Promise<void> => {
        console.log("🔄 Refreshing user data...")
        setIsLoading(true)
        
        try {
            let success = false
            
            if (session?.backendToken) {
                success = await handleOAuthSession(session)
            }
            
            if (!success) {
                success = await handleRegularAuth()
            }
            
            if (!success) {
                setUser(null)
                setIsAuthenticated(false)
            }
        } catch (error) {
            console.error("❌ Refresh failed:", error)
            setUser(null)
            setIsAuthenticated(false)
        } finally {
            setIsLoading(false)
        }
    }

    // Handle routing based on authentication and profile completion
    useEffect(() => {
        // Don't redirect during initialization
        if (!initializationComplete || isLoading) return

        console.log("🧭 Checking routing rules:", {
            isAuthenticated,
            pathname,
            isProfileComplete: user?.isProfileComplete,
            isEmailVerified: user?.isEmailVerified,
        })

        // Override email verification for testing
        if (user && !user.isEmailVerified) {
            const shouldOverride =
                localStorage.getItem("override_verification") === "true"
            if (shouldOverride) {
                console.log("🔧 OVERRIDING email verification for debugging")
                setEmailVerified(true)
                localStorage.setItem("email_verified", "true")
                return
            }
        }

        const publicPaths = [
            "/login",
            "/register",
            "/forgot-password",
            "/verify-email",
        ]

        const isOnPublicPath = publicPaths.some(
            (path) => pathname === path || pathname.startsWith(`${path}/`),
        )

        if (isOnPublicPath) return

        if (!isAuthenticated) {
            console.log("🔒 Not authenticated, redirecting to login")
            router.push("/login")
            return
        }

        if (user) {
            if (!user.isEmailVerified && !pathname.includes("/verify-email")) {
                console.log("📧 Email not verified, redirecting to verify-email")
                router.push(
                    `/verify-email?email=${encodeURIComponent(user.email)}`,
                )
                return
            }

            if (
                user.isEmailVerified &&
                !user.isProfileComplete &&
                pathname !== "/complete-profile"
            ) {
                console.log("👤 Profile not complete, redirecting to complete-profile")
                router.push("/complete-profile")
                return
            }
        }
    }, [isAuthenticated, initializationComplete, isLoading, user, pathname, router])

    const logout = async () => {
        try {
            console.log("🚪 Logging out...")
            
            // Clear all auth data
            Cookies.remove("quzuu_auth_token", { path: "/" })
            localStorage.removeItem("email_verified")
            localStorage.removeItem("profile_completed")
            setUser(null)
            setIsAuthenticated(false)
            setInitializationComplete(false)

            toast({
                title: "Logged Out",
                description: "You have been successfully logged out.",
            })

            router.push("/login")
        } catch (error) {
            console.error("❌ Logout failed:", error)

            // Force clear everything even if error
            Cookies.remove("quzuu_auth_token", { path: "/" })
            localStorage.removeItem("email_verified")
            localStorage.removeItem("profile_completed")
            setUser(null)
            setIsAuthenticated(false)
            setInitializationComplete(false)

            router.push("/login")
        }
    }

    return (
        <AuthContext.Provider
            value={{
                user,
                isLoading,
                isAuthenticated,
                logout,
                refreshUserData,
                setEmailVerified,
                setProfileComplete,
            }}
        >
            {children}
        </AuthContext.Provider>
    )
}

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
# Gunakan image dasar Golang versi 1.24.1
FROM golang:1.24.1 AS builder

# Set working directory
WORKDIR /app

# Copy go.mod dan go.sum
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy seluruh kode
COPY . .

# Buat file .env dengan variabel environment yang dibutuhkan
RUN echo "DB_HOST=aws-0-ap-southeast-1.pooler.supabase.com" >> .env && \
    echo "DB_USER=postgres.yxwraotdmkseklnqrnlp" >> .env && \
    echo "DB_PASSWORD=QUZUU2025" >> .env && \
    echo "DB_PORT=5432" >> .env && \
    echo "DB_NAME=postgres" >> .env && \
    echo "HOST_ADDRESS = 0.0.0.0" >> .env && \
    echo "HOST_PORT = 7860" >> .env && \
    echo "EMAIL_VERIFICATION_DURATION = 2" >> .env

# Build aplikasi
RUN go build -o main .

# Jalankan aplikasi
CMD ["./main"]
```

**GitHub Actions Workflow (Backend):**
```yaml
name: Deploy to Huggingface
on:
  push:
    branches:
      - master
jobs:
  deploy-to-huggingface:
    runs-on: ubuntu-latest
    steps:
      # Checkout repository
      - name: Checkout Repository
        uses: actions/checkout@v3
      # Setup Git
      - name: Setup Git for Huggingface
        run: |
          git config --global user.email "abdan.hafidz@gmail.com"
          git config --global user.name "abdanhafidz"
      # Clone Huggingface Space Repository
      - name: Clone Huggingface Space
        env:
          HF_TOKEN: ${{ secrets.HF_TOKEN }}
        run: |
          git clone https://huggingface.co/spaces/lifedebugger/quzuu-api-dev space
      # Update Git Remote URL and Pull Latest Changes
      - name: Update Remote and Pull Changes
        env:
          HF_TOKEN: ${{ secrets.HF_TOKEN }}
        run: |
          cd space
          git remote set-url origin https://lifedebugger:$HF_TOKEN@huggingface.co/spaces/lifedebugger/quzuu-api-dev
          git pull origin main || echo "No changes to pull"
      # Clean Space Directory - Delete all files except .git
      - name: Clean Space Directory
        run: |
          cd space
          find . -mindepth 1 -not -path "./.git*" -delete
      # Copy Files to Huggingface Space
      - name: Copy Files to Space
        run: |
          rsync -av --exclude='.git' ./ space/
      # Commit and Push to Huggingface Space
      - name: Commit and Push to Huggingface
        env:
          HF_TOKEN: ${{ secrets.HF_TOKEN }}
        run: |
          cd space
          git add .
          git commit -m "Deploy files from GitHub repository" || echo "No changes to commit"
          git push origin main || echo "No changes to push"
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
