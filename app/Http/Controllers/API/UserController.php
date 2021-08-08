<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use App\Http\Controllers\Controller;
use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Laravel\Fortify\Rules\Password;

class UserController extends Controller
{
    public function register(Request $request)
    {
        DB::enableQueryLog();
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'username' => ['required', 'string', 'max:255', 'unique:users,username'],
            'email' => ['required', 'string', 'email', 'max:255', 'unique:users,email'],
            'phone' => ['nullable', 'string', 'max:255'],
            'password' => ['required', 'string', new Password],
        ]);


        try {
            // User::create(
            //     [
            //         'name' => $request->name,
            //         'username' => $request->username,
            //         'email' => $request->email,
            //         'phone' => $request->phone,
            //         'password' => Hash::make($request->password),
            //     ]
            // );
            DB::beginTransaction();

            $user = new User();
            $user->name = $request->name;
            $user->email = $request->email;
            $user->phone = $request->phone;
            $user->username = $request->username;
            $user->password = Hash::make($request->password);
            $user->save();
            DB::commit();

            $user = User::where('email', $request->email)->first();

            $tokenResult = $user->createToken('authToken')->plainTextToken;

            Log::info($request->email . ' [Registrasi User] success', ['query' => DB::getQueryLog()]);
            return ResponseFormatter::success(
                [
                    'access_token' => $tokenResult,
                    'token_type' => 'Bearer',
                    'user' => $user,
                ],
                'User registered'
            );
        } catch (Exception $error) {
            DB::rollBack();
            Log::error($request->email . ' [Registrasi User] failed', ['error' => DB::getQueryLog()]);

            return ResponseFormatter::error(
                [
                    'error' => $error,
                    'message' => $error->getMessage(),
                ],
                'Authentication Failed',
                500,
            );
        }
    }


    public function login(Request $request)
    {
        DB::enableQueryLog();

        try {
            $request->validate([
                'email' => 'email|required',
                'password' => 'required',
            ]);
            $credentials = request(['email', 'password']);
            if (!Auth::attempt($credentials)) {
                return ResponseFormatter::error([
                    'message' => 'Unauthorized'
                ], 'Authentication Failed', 500);
            }

            $user = User::where('email', $request->email)->first();

            if (!Hash::check($request->password, $user->password)) {
                throw new Exception('Invalid Credentials');
            }

            $tokenResult = $user->createToken('authToken')->plainTextToken;
            Log::info($request->email . ' [Login User] success', ['error' => DB::getQueryLog()]);

            return ResponseFormatter::success([
                'access_token' => $tokenResult,
                'token_type' => 'Bearer',
                'user' => $user,
            ], 'Authenticated');
        } catch (Exception $error) {
            Log::error($request->email . ' [Login User] failed', ['error' => DB::getQueryLog()]);

            return ResponseFormatter::error([
                'error' => $error,
                'message' => $error->getMessage(),
            ], 'Authentication Failed', 500);
        }
    }


    public function fetch(Request $request)
    {
        return ResponseFormatter::success($request->user(), 'Data profile user berhasil diambil');
    }

    public function updateProfile(Request $request)
    {
        $data = $request->all();
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'username' => ['required', 'string', 'max:255', 'unique:users,username'],
            'phone' => ['nullable', 'string', 'max:255'],
        ]);

        $user = Auth::user();
        $user->update($data);

        return ResponseFormatter::success(
            $user,
            'Data Profile Berhasil di update'
        );
    }

    public function logout(Request $request)
    {
        $token = $request->user()->currentAccessToken()->delete();

        return ResponseFormatter::success($token, 'Token Revoked');
    }
}
