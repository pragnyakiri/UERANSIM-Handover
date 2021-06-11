//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#include "task.hpp"

#include <ue/app/task.hpp>
#include <ue/nas/task.hpp>
#include <ue/rrc/task.hpp>
#include <utils/common.hpp>
#include <utils/constants.hpp>

namespace nr::ue
{

UeRlsTask::UeRlsTask(TaskBase *base) : m_base{base}
{
    m_logger = m_base->logBase->makeUniqueLogger(m_base->config->getLoggerPrefix() + "rls");

    m_shCtx = new RlsSharedContext();
    m_shCtx->sti = utils::Random64();

    m_udpTask = new RlsUdpTask(base, m_shCtx, base->config->gnbSearchList);
    m_ctlTask = new RlsControlTask(base, m_shCtx);

    m_udpTask->initialize(m_ctlTask);
    m_ctlTask->initialize(this, m_udpTask);
}

void UeRlsTask::onStart()
{
    m_udpTask->start();
    m_ctlTask->start();
}

void UeRlsTask::onLoop()
{
    NtsMessage *msg = take();
    if (!msg)
        return;

    switch (msg->msgType)
    {
    case NtsMessageType::UE_RLS_TO_RLS: {
        auto *w = dynamic_cast<NmUeRlsToRls *>(msg);
        switch (w->present)
        {
        case NmUeRlsToRls::SIGNAL_CHANGED: {
            auto *m = new NmUeRlsToRrc(NmUeRlsToRrc::SIGNAL_CHANGED);
            m->cellId = w->cellId;
            m->dbm = w->dbm;
            m_base->rrcTask->push(m);
            break;
        }
        case NmUeRlsToRls::DOWNLINK_DATA: {
            auto *m = new NmUeRlsToNas(NmUeRlsToNas::DATA_PDU_DELIVERY);
            m->psi = w->psi;
            m->pdu = std::move(w->data);
            m_base->nasTask->push(m);
            break;
        }
        case NmUeRlsToRls::DOWNLINK_RRC: {
            auto *m = new NmUeRlsToRrc(NmUeRlsToRrc::DOWNLINK_RRC_DELIVERY);
            m->cellId = w->cellId;
            m->channel = w->rrcChannel;
            m->pdu = std::move(w->data);
            m_base->rrcTask->push(m);
            break;
        }
        case NmUeRlsToRls::RADIO_LINK_FAILURE: {
            auto *m = new NmUeRlsToRrc(NmUeRlsToRrc::RADIO_LINK_FAILURE);
            m->rlfCause = w->rlfCause;
            m_base->rrcTask->push(m);
            break;
        }
        case NmUeRlsToRls::TRANSMISSION_FAILURE: {
            m_logger->debug("transmission failure [%d]", w->pduList.size());
            break;
        }
        default: {
            m_logger->unhandledNts(msg);
            break;
        }
        }
        break;
    }
    case NtsMessageType::UE_RRC_TO_RLS: {
        auto *w = dynamic_cast<NmUeRrcToRls *>(msg);
        switch (w->present)
        {
        case NmUeRrcToRls::ASSIGN_CURRENT_CELL: {
            auto *m = new NmUeRlsToRls(NmUeRlsToRls::ASSIGN_CURRENT_CELL);
            m->cellId = w->cellId;
            m_ctlTask->push(m);
            break;
        }
        case NmUeRrcToRls::RRC_PDU_DELIVERY: {
            auto *m = new NmUeRlsToRls(NmUeRlsToRls::UPLINK_RRC);
            m->cellId = w->cellId;
            m->rrcChannel = w->channel;
            m->pduId = w->pduId;
            m->data = std::move(w->pdu);
            m_ctlTask->push(m);
            break;
        }
        case NmUeRrcToRls::RESET_STI: {
            m_shCtx->sti = utils::Random64();
            break;
        }
        }
        break;
    }
    case NtsMessageType::UE_NAS_TO_RLS: {
        auto *w = dynamic_cast<NmUeNasToRls *>(msg);
        switch (w->present)
        {
        case NmUeNasToRls::DATA_PDU_DELIVERY: {
            auto *m = new NmUeRlsToRls(NmUeRlsToRls::UPLINK_DATA);
            m->psi = w->psi;
            m->data = std::move(w->pdu);
            m_ctlTask->push(m);
            break;
        }
        }
        break;
    }
    default:
        m_logger->unhandledNts(msg);
        break;
    }

    delete msg;
}

void UeRlsTask::onQuit()
{
    m_udpTask->quit();
    m_ctlTask->quit();

    delete m_udpTask;
    delete m_ctlTask;

    delete m_shCtx;
}

} // namespace nr::ue
