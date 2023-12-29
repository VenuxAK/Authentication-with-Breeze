<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class AuthenticatedSessionController extends Controller
{
    /**
     * Handle an incoming authentication request.
     */
    public function store(LoginRequest $request): JsonResponse
    {
        $request->authenticate();

        $user = User::where("email", $request->email)->first();

        $token_exp = now()->addMinutes(env("SESSION_LIFETIME", 60));
        $token = $user->createToken("Token of $user->name", ["*"], $token_exp)->plainTextToken;

        return response()->json([
            "status" => "OK",
            "code" => 200,
            "token" => $token,
            "expired_at" => now()->addMinutes(env("SESSION_LIFETIME", 60))->format('Y-m-d H:i:s')
        ], 200);
    }

    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): Response
    {
        $request->user()->currentAccessToken()->delete();

        return response()->noContent();
    }
}
