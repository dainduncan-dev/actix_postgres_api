use actix_web::{web, App, HttpServer};
use sqlx::postgres::PgPoolOptions;
use std::env;
use dotenv::dotenv;

mod handlers;
mod auth;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .expect("Failed to create pool.");

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .configure(handlers::init_routes)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
