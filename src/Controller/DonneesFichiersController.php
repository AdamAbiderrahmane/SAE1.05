<?php

namespace App\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class DonneesFichiersController extends AbstractController
{
    #[Route('/donnees/fichiers', name: 'app_donnees_fichiers')]
    public function index(): Response
    {
        return $this->render('donnees_fichiers/index.html.twig', [
            'controller_name' => 'DonneesFichiersController',
        ]);
    }
}
