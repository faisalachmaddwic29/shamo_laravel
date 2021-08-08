<?php

use App\Http\Controllers\API\ProductController;
use App\Http\Controllers\API\TransactionController;
use App\Http\Controllers\API\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/


// DEFAULT
// Route::middleware('auth:sanctum')->get('/user', function (Request $request) {
//     return $request->user();
// });


Route::post('register', [UserController::class, 'register']);
Route::post('login', [UserController::class, 'login']);
Route::get('products', [ProductController::class, 'all']);
Route::get('categories', [ProductController::class, 'all']);


Route::middleware('auth:sanctum')->group(function () {
    Route::get('users', [UserController::class, 'fetch']);
    Route::post('users', [UserController::class, 'updateProfile']);
    Route::post('logout', [UserController::class, 'logout']);


    Route::get('transactions', [TransactionController::class, 'all']);
    Route::post('checkout', [TransactionController::class, 'checkout']);
});




Route::get('test', function () {
    return response()->json(['data' => 'kocak'], 200);
});
