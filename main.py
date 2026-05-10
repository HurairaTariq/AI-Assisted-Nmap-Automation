from app.routers import auth

app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])