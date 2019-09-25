<?php

namespace hiqdev\rdap\WhoisProxy\Provider;

use hiqdev\rdap\core\Domain\Constant\EventAction;
use hiqdev\rdap\core\Domain\Constant\Role;
use hiqdev\rdap\core\Domain\Constant\Status;
use hiqdev\rdap\core\Domain\Entity\Domain;
use hiqdev\rdap\core\Domain\Entity\Entity;
use hiqdev\rdap\core\Domain\Entity\Nameserver;
use hiqdev\rdap\core\Domain\ValueObject\DomainName;
use hiqdev\rdap\core\Domain\ValueObject\Event;
use hiqdev\rdap\core\Infrastructure\Provider\DomainProviderInterface;
use Iodev\Whois\Modules\Tld\DomainInfo;
use Iodev\Whois\Whois;
use JeroenDesloovere\VCard\VCard;

class WhoisDomainProvider implements DomainProviderInterface
{
    /**
     * @var Whois
     */
    private $whois;

    public function __construct(Whois $whois)
    {
        $this->whois = $whois;
    }

    public function get(DomainName $domainName): Domain
    {
        /** @var DomainInfo $domainInfo */
        $domainInfo = $this->whois->loadDomainInfo($domainName->toLDH());
        if (!$domainInfo) {
            throw new \Exception('domain is not available');
        }
        $domain = new Domain(DomainName::of($domainInfo->getDomainName()));
        foreach ($domainInfo->getNameServers() as $nameServer) {
            $domain->addNameserver(new Nameserver(DomainName::of($nameServer)));
        }
        $statuses = $domainInfo->getStates();
        foreach ($statuses as $state) {
            $domain->addStatus(Status::byName(strtoupper($state)));
        }

        $creationDate = $domainInfo->getCreationDate();
        $expirationDate = $domainInfo->getExpirationDate();
        $registrarInfo = $domainInfo->getRegistrar();
        $ownerInfo = $domainInfo->getOwner();

        $creationEvent = Event::occurred(EventAction::REGISTRATION(), \DateTimeImmutable::createFromMutable((new \DateTime())->setTimestamp($creationDate)));
        $domain->addEvent($creationEvent);
        $expirationEvent = Event::occurred(EventAction::EXPIRATION(), \DateTimeImmutable::createFromMutable((new \DateTime())->setTimestamp($expirationDate)));
        $domain->addEvent($expirationEvent);

        $whoisServer = $domainInfo->getWhoisServer();
        $domain->setPort43(DomainName::of($whoisServer));

        $domain->addEntity($this->getEntity(Role::REGISTRANT(), $ownerInfo));
        $domain->addEntity($this->getEntity(Role::REGISTRAR(), $registrarInfo));

        return $domain;
    }

    private function getEntity(Role $role, string $personInfo): Entity
    {
        $personEntity = new Entity();
        $personVcard = new VCard();
        $personVcard->addCompany($personInfo);
        $personEntity->addVcard($personVcard);
        $personEntity->addRole($role);
        return $personEntity;
    }
}
