<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function login(Request $request)
    {
      try {
        $request->validate([
          'email' => 'email|required',
          'password' => 'required'
        ]);
        $credentials = request(['email', 'password']);
        if (!Auth::attempt($credentials)) {
          return response()->json([
            'status_code' => 403,
            'message' => 'Unauthorized'
          ]);
        }
        $user = User::where('email', $request->email)->first();
        if ( ! Hash::check($request->password, $user->password, [])) {
           throw new Exception('Error in Login');
        }
        $tokenResult = $user->createToken('authToken')->plainTextToken;
        return response()->json([
          'status_code' => 200,
          'access_token' => $tokenResult,
          'token_type' => 'Bearer',
        ]);
      } catch (Exception $error) {
        return response()->json([
          'status_code' => 500,
          'message' => 'Server Error',
           $error
        ]);
      }
    }

    public function register(Request $request)
    {
      try {
        $request->validate([
          'first_name' => 'string',
          'last_name' => 'string',
          'email' => 'email|required',
          'password' => 'required'
        ]);

        if(User::Where('email',$request->email)->count() > 0) throw new Exception('Email already exists');

        $user = new User();
        $user->fill($request->all());
        $user->password = Hash::make($request->password);
        $user->save();

        $tokenResult = $user->createToken('authToken')->plainTextToken;

        return response()->json([
          'status_code' => 200,
          'access_token' => $tokenResult,
          'token_type' => 'Bearer',
        ]);
      } catch (Exception $error) {
        return response()->json([
          'status_code' => 500,
          'message' => 'Server Error',
          $error
        ]);
      }
    }
}
