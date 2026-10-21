# CareerTrack — Job & Internship Application Tracker
## Complete Java + JDBC + MySQL Student Course Project

CareerTrack is a complete, college-level job and internship application tracker designed to align directly with your **Java** and **DBMS** course syllabus.

---

## Project Structure

```text
backend/
├── server.ts                      (TypeScript/Express application server)
└── src/
    ├── model/                     (OOP Data Models)
    │   ├── Company.java           (Encapsulated company entity)
    │   ├── Application.java       (Abstract parent class)
    │   ├── JobApplication.java    (Child class overriding showDetails)
    │   ├── InternshipApplication.java (Child class overriding showDetails)
    │   ├── Interview.java         (Overloaded constructors)
    │   └── Offer.java             (Offer metrics & status)
    ├── dao/                       (Data Access Layer & Interfaces)
    │   ├── CompanyDAO.java        (Interface contract)
    │   ├── CompanyDAOImpl.java    (PreparedStatement & JDBC implementation)
    │   ├── ApplicationDAO.java    (Interface contract)
    │   ├── ApplicationDAOImpl.java
    │   ├── InterviewDAO.java      (Interface contract)
    │   ├── InterviewDAOImpl.java
    │   ├── OfferDAO.java          (Interface contract)
    │   └── OfferDAOImpl.java
    ├── util/                      (Utilities & Syllabus Demonstrations)
    │   ├── DBConnection.java      (Connection factory & safe cleanup)
    │   ├── InvalidStatusException.java (Custom checked exception)
    │   ├── ReportUtil.java        (Streams API, Lambdas, groupingBy, mapToDouble)
    │   ├── JsonUtil.java          (Zero-dependency JSON serializer)
    │   └── WebServer.java         (Built-in HttpServer REST bridge)
    └── main/
        └── Main.java              (Single JVM entry point & Scanner console menu)

database/
├── schema.sql
├── sample_data.sql
├── queries.sql
└── plsql.sql
```

---

## 🚀 Setup & Execution Guide

### 1. Database Setup in MySQL
The Java application connects to the existing `job_tracker` MySQL database. The Companies directory and company-to-role lookup use the existing `companies.role_offered` column; application records continue to use the existing `applications.company_id` relationship and `applications.role` field. No migration is required when those columns are already present.

**Do not run `database/schema.sql` against an existing database.** It drops and recreates `job_tracker`, which would delete existing records. Do not source the sample-data script into a database containing user data.

### 2. Configure Database Credentials
Set `DB_URL`, `DB_USER`, and `DB_PASSWORD` in the environment before starting the server. Defaults target `job_tracker` on local MySQL as `root` with an empty password. The server checks the database connection and required `user_details` and `companies` columns before listening on port 8080.

### 3. Locate the MySQL JDBC Driver
The MySQL Connector/J JAR must be on both the compiler and runtime classpaths. You can place the JAR at `backend/lib/mysql-connector-j.jar` or point `MYSQL_JDBC_JAR` to an existing copy, such as the Maven-cached JAR on macOS:

```bash
MYSQL_JDBC_JAR="$HOME/.m2/repository/com/mysql/mysql-connector-j/8.4.0/mysql-connector-j-8.4.0.jar"
```

### 4. Compile and Run the Web Application
Run from the project root. Use the **same JDBC JAR** for compilation and runtime; without it, database operations cannot work. Stop any existing server already using port 8080 before starting another.

```bash
MYSQL_JDBC_JAR="$HOME/.m2/repository/com/mysql/mysql-connector-j/8.4.0/mysql-connector-j-8.4.0.jar"
mkdir -p backend/out
javac -cp "$MYSQL_JDBC_JAR" -d backend/out $(find backend/src -name '*.java')
java -cp "backend/out:$MYSQL_JDBC_JAR" util.WebServer
```

If using a JAR in `backend/lib`, set `MYSQL_JDBC_JAR=backend/lib/mysql-connector-j.jar` instead. On Windows, use `;` rather than `:` to separate runtime classpath entries.

Open `http://localhost:8080`. The dashboard requires an existing account or a new account created through Register; the company list and company detail API are protected by the existing session authentication.

---

## 🎯 Viva Q&A Cheat Sheet (Organized by Syllabus Units)

### Java Portions

#### UNIT I: Java Architecture & Fundamentals
- **Q: What is the entry point of your program, and how does it execute on the JVM?**
  - **A:** `public static void main(String[] args)` in `Main.java` serves as the single entry point. The Java compiler (`javac`) transforms source code into bytecode (`.class` files in `out/`), which the Java Virtual Machine (JVM) interprets and executes with its JIT (Just-In-Time) compiler.
- **Q: Where did you use standard I/O streams?**
  - **A:** In `Main.java`, console input is read via `System.in` (an `InputStream` byte stream) wrapped by `java.util.Scanner` for convenient character-level parsing, and output is displayed via `System.out` (a `PrintStream` character/byte stream).

#### UNIT II: Classes, Inheritance & Abstract Classes
- **Q: Why is `Application.java` an abstract class?**
  - **A:** An application in real life is either a full-time position or an internship. `Application` defines common state (`applicationId`, `companyId`, `role`, `status`) and an abstract method `public abstract String showDetails();`.
- **Q: Where is method overriding demonstrated?**
  - **A:** Both `JobApplication` and `InternshipApplication` extend `Application` and override `showDetails()` and `toString()`. When calling `a.showDetails()`, dynamic method dispatch invokes the child class's specific implementation at runtime.

#### UNIT III: Packages, Interfaces & Exception Handling
- **Q: How are packages and access protection organized?**
  - **A:** Four packages (`model`, `dao`, `util`, `main`). Fields in `model` are `private` or `protected`, exposed via public getters/setters. DAO implementations implement DAO interfaces.
- **Q: Explain your custom exception.**
  - **A:** `InvalidStatusException` extends `Exception` (checked exception). In `ReportUtil.validateStatus()`, if the status is not in the allowed set, it is thrown with `throw new InvalidStatusException(...)`. In `Main.java`, it is caught with `try-catch` to inform the user gracefully.
- **Q: Why use `finally` in database operations?**
  - **A:** Even if an SQL query throws an exception, the `finally` block is guaranteed to execute, ensuring `ps.close()` and `con.close()` are called to prevent connection leaks.

#### UNIT IV: Collections & Iterator
- **Q: Which collections did you use?**
  - **A:** `ArrayList` for storing retrieved records from MySQL, `HashMap` for storing grouping results (e.g. applications per company), and `HashSet` for validation sets.
- **Q: Where is `Iterator` used?**
  - **A:** In `ReportUtil.printSummaryReportWithIterator()`, an `Iterator<Map.Entry<String, Long>>` traverses the status breakdown entries using `hasNext()` and `next()`.

#### UNIT V: Streams API, Lambdas & JDBC
- **Q: Where did you use Lambda expressions and Predicate?**
  - **A:** In `ReportUtil.filterApplications()`, which takes `Predicate<Application> condition` and uses `app -> app.getStatus().equalsIgnoreCase(status)`.
- **Q: Explain `groupingBy` and finding the highest package.**
  - **A:** Applications are grouped with `applications.stream().collect(Collectors.groupingBy(Application::getStatus, Collectors.counting()))`. Offers use `offers.stream().mapToDouble(Offer::getPackageLpa).max()`, with the resulting `OptionalDouble` handled safely.
- **Q: What is a `PreparedStatement` and why use it over `Statement`?**
  - **A:** A `PreparedStatement` is precompiled by the database engine, executes faster for repeated queries, and uses placeholder parameters (`?`) to prevent SQL Injection attacks.

---

### DBMS Portions

#### UNIT I: Keys, Constraints & Views
- **Q: What constraints did you enforce?**
  - **A:** Primary Key (`AUTO_INCREMENT`), Foreign Key (`ON DELETE CASCADE`), Unique constraints on contact email and `offers.application_id`, a positive package check, and `ENUM` domain constraints.
- **Q: What is the purpose of your SQL views?**
  - **A:** `view_application_details` provides a joined abstraction over applications, companies, and offers; `view_status_summary` provides grouped metrics; and `view_upcoming_followups` selects upcoming follow-ups.

#### UNIT II: Relational Queries
- The project includes SQL queries for application lookup, filtering, status summaries, and company-level reporting in `database/queries.sql`.

#### UNIT III: Stored Procedures
- Stored procedure examples are provided in `database/plsql.sql`.
