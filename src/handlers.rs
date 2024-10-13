use actix_web::{web, HttpMessage, HttpResponse, Responder, HttpRequest};
use sqlx::{PgPool, FromRow};
use serde_json;
use std::fs;
use serde::Deserialize;
use crate::auth::{hash_password, verify_password, Claims};

#[derive(FromRow, Debug, serde::Serialize, serde::Deserialize)]
pub struct User {
    id: i32,
    name: String,
    email: String,
    password_hash: String,
}

pub async fn get_users(pool: web::Data<PgPool>) -> impl Responder {
    let users = sqlx::query_as!(
        User,
        "SELECT id, name, email, password_hash FROM users"
    )
    .fetch_all(pool.get_ref())
    .await
    .expect("Failed to fetch users");

    HttpResponse::Ok().json(users)
}

pub async fn get_user_by_id(pool: web::Data<PgPool>, path: web::Path<i32>) -> impl Responder {
    let user_id = path.into_inner();
    let user = sqlx::query_as!(
        User,
        "SELECT id, name, email, password_hash FROM users WHERE id = $1",
        user_id
    )
    .fetch_one(pool.get_ref())
    .await
    .expect("Failed to fetch user");
    HttpResponse::Ok().json(user)
}

pub async fn update_user(
    pool: web::Data<PgPool>,
    path: web::Path<i32>,
    form: web::Form<User>,
) -> impl Responder {
    let user_id = path.into_inner();
    let user = form.into_inner();
    sqlx::query!(
        "UPDATE users SET name = $1, email = $2, password_hash = $3 WHERE id = $4",
        user.name,
        user.email,
        user.password_hash,
        user_id
    )
    .execute(pool.get_ref())
    .await
    .expect("Failed to update user");

    HttpResponse::Ok().json(serde_json::json!({ "message": "User updated" }))
}

#[derive(Deserialize, Debug, serde::Serialize)]
pub struct RegisterForm {
    name: String,
    email: String,
    password: String,
}

#[derive(Deserialize, Debug)]
pub struct LoginForm {
    email: String,
    password: String,
}

pub async fn register_user(pool: web::Data<PgPool>, form: web::Form<RegisterForm>) -> impl Responder {
    let name = &form.name;
    let email = &form.email;
    let password = &form.password;

    let password_hash = hash_password(password).expect("Failed to hash password");

    sqlx::query!(
        "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3)",
        name,
        email,
        password_hash
    )
    .execute(pool.get_ref())
    .await
    .expect("Failed to insert user");

    HttpResponse::Created().json(serde_json::json!({ "message": "User created" }))
}

pub async fn login_user(pool: web::Data<PgPool>, form: web::Form<LoginForm>) -> impl Responder {
    let email = &form.email;
    let password = &form.password;

    let record = sqlx::query!(
        "SELECT password_hash FROM users WHERE email = $1",
        email
    )
    .fetch_one(pool.get_ref())
    .await
    .expect("Failed to fetch user");

    let is_valid = verify_password(&record.password_hash, password).expect("Failed to verify password");

    if is_valid {
        HttpResponse::Ok().json(serde_json::json!({ "message": "Login successful" }))
    } else {
        HttpResponse::Unauthorized().body("Invalid credentials")
    }
}

pub async fn register_page() -> impl Responder {
    let html_content = fs::read_to_string("src/views/register.html")
        .unwrap_or_else(|_| "Error loading page".to_string());
    HttpResponse::Ok().content_type("text/html").body(html_content)
}

pub async fn login_page() -> impl Responder {
    let html_content = fs::read_to_string("src/views/login.html")
        .unwrap_or_else(|_| "Error loading page".to_string());
    HttpResponse::Ok().content_type("text/html").body(html_content)
}

pub async fn delete_user(
    pool: web::Data<PgPool>,
    path: web::Path<i32>,
    req: HttpRequest,
) -> impl Responder {
    let user_id = path.into_inner();
    let id_str = user_id.to_string();
    
    if let Some(claims) = req.extensions().get::<Claims>() {
        let claims_sub = &claims.sub;

        if &id_str == claims_sub || claims.roles.contains(&"admin".to_string()) {
            let result = sqlx::query!(
                "DELETE FROM users WHERE id = $1",
                user_id
            )
            .execute(pool.get_ref())
            .await;

            match result {
                Ok(_) => HttpResponse::Ok().body(format!("User {} deleted", user_id)),
                Err(e) => HttpResponse::InternalServerError().body(format!("Error deleting user: {}", e)),
            }
        } else {
            HttpResponse::Forbidden().body("Forbidden")
        }
    } else {
        HttpResponse::Unauthorized().body("Unauthorized")
    }
}

pub async fn add_admin_role_to_user(
    pool: web::Data<PgPool>,
    path: web::Path<i32>,
    req: HttpRequest,
) -> impl Responder {
    let user_id = path.into_inner();
    if let Some(claims) = req.extensions().get::<Claims>() {
        if claims.roles.contains(&"admin".to_string()) {
            let result = sqlx::query!(
                "UPDATE users SET roles = ARRAY['admin'] WHERE id = $1",
                user_id
            )
            .execute(pool.get_ref())
            .await;

            match result {
                Ok(_) => HttpResponse::Ok().body("Admin role added to user"),
                Err(e) => HttpResponse::InternalServerError().body(format!("Error: {}", e)),
            }
        } else {
            println!("User is not an admin");
            HttpResponse::Forbidden().body("Forbidden")
        }
    } else {
        println!("No claims found");
        HttpResponse::Unauthorized().body("Unauthorized")
    }
}

 pub fn init_routes(cfg: &mut web::ServiceConfig) {
    cfg.route("/", web::get().to(|| async { "Hello, world!" }))
        .route("/users", web::get().to(get_users))
        .route("/users/{id}/add-admin", web::post().to(add_admin_role_to_user))
        .route("/users/{id}", web::get().to(get_user_by_id))
        .route("/users/{id}", web::put().to(update_user))
        .route("/users/{id}", web::delete().to(delete_user))
        .route("/register", web::get().to(register_page))
        .route("/register", web::post().to(register_user))
        .route("/login", web::get().to(login_page))
        .route("/login", web::post().to(login_user));
}

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, web, App};
    use sqlx::{PgPool, Executor};
    use std::env;

    async fn setup_test_db() -> PgPool {
        dotenv::dotenv().ok();
        let database_url = env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL must be set");
        let pool = PgPool::connect(&database_url).await.expect("Failed to connect to test database");

        // Use a transaction to ensure all operations are atomic
        let mut tx = pool.begin().await.unwrap();

        // Drop and recreate the users table
        tx.execute("DROP TABLE IF EXISTS users")
            .await
            .unwrap();

        tx.execute(
            "CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                name VARCHAR NOT NULL,
                email VARCHAR NOT NULL UNIQUE,
                password_hash VARCHAR NOT NULL,
                roles TEXT[] DEFAULT '{}'
            )"
        )
        .await
        .unwrap();

        // Commit the transaction
        tx.commit().await.unwrap();

        pool
    }

    #[actix_web::test]
    async fn test_get_user_by_id() {
        let pool = setup_test_db().await;

        // Insert test data
        let user = sqlx::query!(
            "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id, name, email, password_hash",
            "Test User",
            "test_get_user_by_id@example.com",
            "hashed_password"
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/users/{id}", web::get().to(get_user_by_id))
        ).await;

        let req = test::TestRequest::get()
            .uri(&format!("/users/{}", user.id))
            .to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let body_bytes = test::read_body(resp).await;
        let body: User = serde_json::from_slice(&body_bytes).expect("Failed to deserialize response");

        assert_eq!(body.name, "Test User");
    }

    #[actix_web::test]
    async fn test_update_user() {
        let pool = setup_test_db().await;

        let user = sqlx::query!(
            "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
            "Test User",
            "test@example.com",
            "hashed_password"
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/users/{id}", web::put().to(update_user))
        ).await;

        let req = test::TestRequest::put()
            .uri(&format!("/users/{}", user.id))
            .set_form(&User {
                id: user.id,
                name: "Updated User".to_string(),
                email: "updated@example.com".to_string(),
                password_hash: "new_hashed_password".to_string()
            })
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let body_bytes = test::read_body(resp).await;
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("Failed to deserialize response");

        assert_eq!(body["message"], "User updated");
    }

    #[actix_web::test]
    async fn test_delete_user() {
        let pool = setup_test_db().await;

        // Insert test data without specifying the ID
        let user = sqlx::query!(
            "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
            "Test User",
            "test_delete_user@example.com",
            "hashed_password"
        )
        .fetch_one(&pool)
        .await
        .unwrap();

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/users/{id}", web::delete().to(delete_user))
        ).await;

        // Create a test request and insert mock claims
        let req = test::TestRequest::delete()
            .uri(&format!("/users/{}", user.id))
            .to_request();

        // Insert mock claims into the request
        req.extensions_mut().insert(Claims {
            sub: user.id.to_string(),
            roles: vec!["admin".to_string()],
        });

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let body_bytes = test::read_body(resp).await;
        let body: String = String::from_utf8(body_bytes.to_vec()).expect("Failed to convert response to String");

        assert_eq!(body, format!("User {} deleted", user.id));
    }

    #[actix_web::test]
    async fn test_register_user() {
        let pool = setup_test_db().await;

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/register", web::post().to(register_user))
        ).await;

        let req = test::TestRequest::post()
            .uri("/register")
            .set_form(&RegisterForm {
                name: "New User".to_string(),
                email: "newuser@example.com".to_string(),
                password: "password123".to_string()
            })
            .to_request();

        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let body_bytes = test::read_body(resp).await;

        let body: serde_json::Value = serde_json::from_slice(&body_bytes).expect("Failed to deserialize response");

        assert_eq!(body["message"], "User created");
    }

    #[actix_web::test]
    async fn test_get_users() {
        let pool = setup_test_db().await;

        // Clear the users table before the test
        sqlx::query!("DELETE FROM users")
            .execute(&pool)
            .await
            .expect("Failed to clear users table");

        // Insert a single test user
        sqlx::query!(
            "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3)",
            "Test User",
            "test_get_users@example.com",
            "hashed_password"
        )
        .execute(&pool)
        .await
        .expect("Failed to insert test user");

        let app = test::init_service(
            App::new()
                .app_data(web::Data::new(pool.clone()))
                .route("/users", web::get().to(get_users))
        ).await;

        let req = test::TestRequest::get().uri("/users").to_request();
        let resp = test::call_service(&app, req).await;

        assert!(resp.status().is_success());

        let body_bytes = test::read_body(resp).await;
        let body: Vec<User> = serde_json::from_slice(&body_bytes).expect("Failed to deserialize response");

        assert_eq!(body.len(), 1, "Expected 1 user, but found {}", body.len());
        assert_eq!(body[0].name, "Test User");
        assert_eq!(body[0].email, "test_get_users@example.com");
    }
}
