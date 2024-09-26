<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = '/auth';

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    /**
     * Override the credentials method to compare passwords directly.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return array
     */
    protected function credentials(Request $request)
    {
        return $request->only($this->username(), 'password');
    }

    /**
     * Override the authenticated method to handle authentication without hashing.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  mixed  $user
     * @return mixed
     */
    protected function authenticated(Request $request, $user)
    {
        // Authentifie l'utilisateur sans utiliser le hachage
        return redirect()->intended($this->redirectTo);
    }

    /**
     * Override the login method to handle password checking directly.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function login(Request $request)
    {
        // Valider les informations d'identification
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        // Trouver l'utilisateur par son email
        $user = \App\Models\User::where('email', $request->email)->first();

        // Vérifier si l'utilisateur existe et si le mot de passe est correct
        if ($user && $user->password === $request->password) {
            Auth::login($user); // Authentifie l'utilisateur
            return redirect()->intended($this->redirectTo);
        }

        // Gestion des erreurs d'authentification
        return back()->withErrors([
            'email' => 'Les informations d\'identification fournies sont incorrectes.',
        ]);
    }
}
