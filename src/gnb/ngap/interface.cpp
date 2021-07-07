//
// This file is a part of UERANSIM open source project.
// Copyright (c) 2021 ALİ GÜNGÖR.
//
// The software and all associated files are licensed under GPL-3.0
// and subject to the terms and conditions defined in LICENSE file.
//

#include "task.hpp"
#include "utils.hpp"

#include <algorithm>

#include <gnb/app/task.hpp>
#include <gnb/rrc/task.hpp>
#include <gnb/sctp/task.hpp>

#include <asn/ngap/ASN_NGAP_AMFConfigurationUpdate.h>
#include <asn/ngap/ASN_NGAP_AMFConfigurationUpdateFailure.h>
#include <asn/ngap/ASN_NGAP_AMFName.h>
#include <asn/ngap/ASN_NGAP_BroadcastPLMNItem.h>
#include <asn/ngap/ASN_NGAP_ErrorIndication.h>
#include <asn/ngap/ASN_NGAP_GlobalGNB-ID.h>
#include <asn/ngap/ASN_NGAP_InitiatingMessage.h>
#include <asn/ngap/ASN_NGAP_NGAP-PDU.h>
#include <asn/ngap/ASN_NGAP_NGSetupRequest.h>
#include <asn/ngap/ASN_NGAP_OverloadStartNSSAIItem.h>
#include <asn/ngap/ASN_NGAP_PLMNSupportItem.h>
#include <asn/ngap/ASN_NGAP_ProtocolIE-Field.h>
#include <asn/ngap/ASN_NGAP_ServedGUAMIItem.h>
#include <asn/ngap/ASN_NGAP_SliceSupportItem.h>
#include <asn/ngap/ASN_NGAP_SupportedTAItem.h>
// Pradnya
#include "encode.hpp"
#include <asn/ngap/ASN_NGAP_UserLocationInformationNR.h>
//#include <asn/ngap/ASN_NGAP_PDUSessionResourceToBeSwitchedDLList.h>
#include <asn/ngap/ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem.h>

namespace nr::gnb
{

template <typename T>
static void AssignDefaultAmfConfigs(NgapAmfContext *amf, T *msg)
{
    auto *ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AMFName);
    if (ie)
        amf->amfName = asn::GetPrintableString(ie->AMFName);

    ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_RelativeAMFCapacity);
    if (ie)
        amf->relativeCapacity = ie->RelativeAMFCapacity;

    ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_ServedGUAMIList);
    if (ie)
    {
        utils::ClearAndDelete(amf->servedGuamiList);

        asn::ForeachItem(ie->ServedGUAMIList, [amf](ASN_NGAP_ServedGUAMIItem &item) {
            auto servedGuami = new ServedGuami();
            if (item.backupAMFName)
                servedGuami->backupAmfName = asn::GetPrintableString(*item.backupAMFName);
            ngap_utils::GuamiFromAsn_Ref(item.gUAMI, servedGuami->guami);
            amf->servedGuamiList.push_back(servedGuami);
        });
    }

    ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_PLMNSupportList);
    if (ie)
    {
        utils::ClearAndDelete(amf->plmnSupportList);

        asn::ForeachItem(ie->PLMNSupportList, [amf](ASN_NGAP_PLMNSupportItem &item) {
            auto plmnSupport = new PlmnSupport();
            ngap_utils::PlmnFromAsn_Ref(item.pLMNIdentity, plmnSupport->plmn);
            asn::ForeachItem(item.sliceSupportList, [plmnSupport](ASN_NGAP_SliceSupportItem &ssItem) {
                plmnSupport->sliceSupportList.slices.push_back(ngap_utils::SliceSupportFromAsn(ssItem));
            });
            amf->plmnSupportList.push_back(plmnSupport);
        });
    }
}

void NgapTask::handleAssociationSetup(int amfId, int ascId, int inCount, int outCount)
{
    auto *amf = findAmfContext(amfId);
    if (amf != nullptr)
    {
        amf->association.associationId = amfId;
        amf->association.inStreams = inCount;
        amf->association.outStreams = outCount;

        sendNgSetupRequest(amf->ctxId);
    }
}

void NgapTask::handleAssociationShutdown(int amfId)
{
    auto *amf = findAmfContext(amfId);
    if (amf == nullptr)
        return;

    m_logger->err("Association terminated for AMF[%d]", amfId);
    m_logger->debug("Removing AMF context[%d]", amfId);

    amf->state = EAmfState::NOT_CONNECTED;

    auto *w = new NmGnbSctp(NmGnbSctp::CONNECTION_CLOSE);
    w->clientId = amfId;
    m_base->sctpTask->push(w);

    deleteAmfContext(amfId);
}

void NgapTask::sendNgSetupRequest(int amfId)
{
    m_logger->debug("Sending NG Setup Request");

    auto *amf = findAmfContext(amfId);
    if (amf == nullptr)
        return;

    amf->state = EAmfState::WAITING_NG_SETUP;

    // TODO: this procedure also re-initialises the NGAP UE-related contexts (if any)
    //  and erases all related signalling connections in the two nodes like an NG Reset procedure would do.
    //  More on 38.413 8.7.1.1

    auto *globalGnbId = asn::New<ASN_NGAP_GlobalGNB_ID>();
    globalGnbId->gNB_ID.present = ASN_NGAP_GNB_ID_PR_gNB_ID;
    asn::SetBitString(globalGnbId->gNB_ID.choice.gNB_ID, octet4{m_base->config->getGnbId()});
    asn::SetOctetString3(globalGnbId->pLMNIdentity, ngap_utils::PlmnToOctet3(m_base->config->plmn));

    auto *ieGlobalGnbId = asn::New<ASN_NGAP_NGSetupRequestIEs>();
    ieGlobalGnbId->id = ASN_NGAP_ProtocolIE_ID_id_GlobalRANNodeID;
    ieGlobalGnbId->criticality = ASN_NGAP_Criticality_reject;
    ieGlobalGnbId->value.present = ASN_NGAP_NGSetupRequestIEs__value_PR_GlobalRANNodeID;
    ieGlobalGnbId->value.choice.GlobalRANNodeID.present = ASN_NGAP_GlobalRANNodeID_PR_globalGNB_ID;
    ieGlobalGnbId->value.choice.GlobalRANNodeID.choice.globalGNB_ID = globalGnbId;

    auto *ieRanNodeName = asn::New<ASN_NGAP_NGSetupRequestIEs>();
    ieRanNodeName->id = ASN_NGAP_ProtocolIE_ID_id_RANNodeName;
    ieRanNodeName->criticality = ASN_NGAP_Criticality_ignore;
    ieRanNodeName->value.present = ASN_NGAP_NGSetupRequestIEs__value_PR_RANNodeName;
    asn::SetPrintableString(ieRanNodeName->value.choice.RANNodeName, m_base->config->name);

    auto *broadcastPlmn = asn::New<ASN_NGAP_BroadcastPLMNItem>();
    asn::SetOctetString3(broadcastPlmn->pLMNIdentity, ngap_utils::PlmnToOctet3(m_base->config->plmn));
    for (auto &nssai : m_base->config->nssai.slices)
    {
        auto *item = asn::New<ASN_NGAP_SliceSupportItem>();
        asn::SetOctetString1(item->s_NSSAI.sST, static_cast<uint8_t>(nssai.sst));
        if (nssai.sd.has_value())
        {
            item->s_NSSAI.sD = asn::New<ASN_NGAP_SD_t>();
            asn::SetOctetString3(*item->s_NSSAI.sD, octet3{nssai.sd.value()});
        }
        asn::SequenceAdd(broadcastPlmn->tAISliceSupportList, item);
    }

    auto *supportedTa = asn::New<ASN_NGAP_SupportedTAItem>();
    asn::SetOctetString3(supportedTa->tAC, octet3{m_base->config->tac});
    asn::SequenceAdd(supportedTa->broadcastPLMNList, broadcastPlmn);

    auto *ieSupportedTaList = asn::New<ASN_NGAP_NGSetupRequestIEs>();
    ieSupportedTaList->id = ASN_NGAP_ProtocolIE_ID_id_SupportedTAList;
    ieSupportedTaList->criticality = ASN_NGAP_Criticality_reject;
    ieSupportedTaList->value.present = ASN_NGAP_NGSetupRequestIEs__value_PR_SupportedTAList;
    asn::SequenceAdd(ieSupportedTaList->value.choice.SupportedTAList, supportedTa);

    auto *iePagingDrx = asn::New<ASN_NGAP_NGSetupRequestIEs>();
    iePagingDrx->id = ASN_NGAP_ProtocolIE_ID_id_DefaultPagingDRX;
    iePagingDrx->criticality = ASN_NGAP_Criticality_ignore;
    iePagingDrx->value.present = ASN_NGAP_NGSetupRequestIEs__value_PR_PagingDRX;
    iePagingDrx->value.choice.PagingDRX = ngap_utils::PagingDrxToAsn(m_base->config->pagingDrx);

    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_NGSetupRequest>(
        {ieGlobalGnbId, ieRanNodeName, ieSupportedTaList, iePagingDrx});

    sendNgapNonUe(amfId, pdu);
}

void NgapTask::receiveNgSetupResponse(int amfId, ASN_NGAP_NGSetupResponse *msg)
{
    m_logger->debug("NG Setup Response received");

    auto *amf = findAmfContext(amfId);
    if (amf == nullptr)
        return;

    AssignDefaultAmfConfigs(amf, msg);

    amf->state = EAmfState::CONNECTED;
    m_logger->info("NG Setup procedure is successful");

    if (!m_isInitialized && std::all_of(m_amfCtx.begin(), m_amfCtx.end(),
                                        [](auto &amfCtx) { return amfCtx.second->state == EAmfState::CONNECTED; }))
    {
        m_isInitialized = true;

        auto *update = new NmGnbStatusUpdate(NmGnbStatusUpdate::NGAP_IS_UP);
        update->isNgapUp = true;
        m_base->appTask->push(update);

        m_base->rrcTask->push(new NmGnbNgapToRrc(NmGnbNgapToRrc::RADIO_POWER_ON));
    }
}

void NgapTask::receiveNgSetupFailure(int amfId, ASN_NGAP_NGSetupFailure *msg)
{
    auto *amf = findAmfContext(amfId);
    if (amf == nullptr)
        return;

    amf->state = EAmfState::WAITING_NG_SETUP;

    auto *ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_Cause);
    if (ie)
        m_logger->err("NG Setup procedure is failed. Cause: %s", ngap_utils::CauseToString(ie->Cause).c_str());
    else
        m_logger->err("NG Setup procedure is failed.");
}

void NgapTask::receiveErrorIndication(int amfId, ASN_NGAP_ErrorIndication *msg)
{
    auto *amf = findAmfContext(amfId);
    if (amf == nullptr)
    {
        m_logger->err("Error indication received with not found AMF context");
        return;
    }

    auto *ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_Cause);
    if (ie)
        m_logger->err("Error indication received. Cause: %s", ngap_utils::CauseToString(ie->Cause).c_str());
    else
        m_logger->err("Error indication received.");
}

void NgapTask::sendErrorIndication(int amfId, NgapCause cause, int ueId)
{
    auto ieCause = asn::New<ASN_NGAP_ErrorIndicationIEs>();
    ieCause->id = ASN_NGAP_ProtocolIE_ID_id_Cause;
    ieCause->criticality = ASN_NGAP_Criticality_ignore;
    ieCause->value.present = ASN_NGAP_ErrorIndicationIEs__value_PR_Cause;
    ngap_utils::ToCauseAsn_Ref(cause, ieCause->value.choice.Cause);

    m_logger->warn("Sending an error indication with cause: %s",
                   ngap_utils::CauseToString(ieCause->value.choice.Cause).c_str());

    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_ErrorIndication>({ieCause});

    if (ueId > 0)
        sendNgapUeAssociated(ueId, pdu);
    else
        sendNgapNonUe(amfId, pdu);
}

// Pradnya
void NgapTask::handoverPreparation(int ueId) 
{

    // Print the various parameters to pass on to handleXnHandover
    m_logger->debug("handoverPreparation ueId: %d", ueId);

    /* Find UE and AMF contexts */

    auto *ue = findUeContext(ueId);
    /*if (ue == nullptr)
    {
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }*/
    m_logger->debug("amfId: %d", ue->associatedAmfId);
    m_logger->debug("ue->amfUeNgapId: %d", ue->amfUeNgapId);
    m_logger->debug("ue->ranUeNgapId: %d", ue->ranUeNgapId);

    auto *amf = findAmfContext(ue->associatedAmfId);
    /*if (amf == nullptr)
    {
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }*/

    m_logger->debug("amf->amfName: %s", amf->amfName.c_str());
    m_logger->debug("amf->ctxId: %d", amf->ctxId);
    m_logger->debug("ue->uplinkStream: %d", ue->uplinkStream);

}

// Pradnya
void NgapTask::handleXnHandover(int asAmfId, int64_t amfUeNgapId, int64_t ranUeNgapId, int ctxtId, int ulStr, std::string amf_name)
{

    m_logger->debug("handle Xn handover asAmfId: %d", asAmfId);
    m_logger->debug("amf_Name: %s", amf_name.c_str());

    auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_PathSwitchRequest>({});

    int ueId = 3;
    //auto *ue = findUeContext(ueId);
    auto *ue = new NgapUeContext(ueId);
    ue->amfUeNgapId = amfUeNgapId;
    ue->ranUeNgapId = ranUeNgapId;
    ue->uplinkStream = ulStr;

    /* Insert UE-related information elements */
    {
        if (amfUeNgapId > 0)
        {
            asn::ngap::AddProtocolIeIfUsable(*pdu, asn_DEF_ASN_NGAP_AMF_UE_NGAP_ID,
                                             ASN_NGAP_ProtocolIE_ID_id_SourceAMF_UE_NGAP_ID, ASN_NGAP_Criticality_reject,
                                             [ue](void *mem) {
                                                 auto &id = *reinterpret_cast<ASN_NGAP_AMF_UE_NGAP_ID_t *>(mem);
                                                 asn::SetSigned64(ue->amfUeNgapId, id);
                                             });
        }

        asn::ngap::AddProtocolIeIfUsable(
            *pdu, asn_DEF_ASN_NGAP_RAN_UE_NGAP_ID, ASN_NGAP_ProtocolIE_ID_id_RAN_UE_NGAP_ID,
            ASN_NGAP_Criticality_reject,
            [ue](void *mem) { *reinterpret_cast<ASN_NGAP_RAN_UE_NGAP_ID_t *>(mem) = ue->ranUeNgapId; });

        asn::ngap::AddProtocolIeIfUsable(
            *pdu, asn_DEF_ASN_NGAP_UserLocationInformation, ASN_NGAP_ProtocolIE_ID_id_UserLocationInformation,
            ASN_NGAP_Criticality_ignore, [this](void *mem) {
                auto *loc = reinterpret_cast<ASN_NGAP_UserLocationInformation *>(mem);
                loc->present = ASN_NGAP_UserLocationInformation_PR_userLocationInformationNR;
                loc->choice.userLocationInformationNR = asn::New<ASN_NGAP_UserLocationInformationNR>();

                auto &nr = loc->choice.userLocationInformationNR;
                //nr->timeStamp = asn::New<ASN_NGAP_TimeStamp_t>();

                ngap_utils::ToPlmnAsn_Ref(m_base->config->plmn, nr->nR_CGI.pLMNIdentity);
                asn::SetBitStringLong<36>(m_base->config->nci, nr->nR_CGI.nRCellIdentity);
                ngap_utils::ToPlmnAsn_Ref(m_base->config->plmn, nr->tAI.pLMNIdentity);
                asn::SetOctetString3(nr->tAI.tAC, octet3{m_base->config->tac});
                //asn::SetOctetString4(*nr->timeStamp, octet4{utils::CurrentTimeStamp().seconds32()});
            });

        asn::ngap::AddProtocolIeIfUsable(
            *pdu, asn_DEF_ASN_NGAP_UESecurityCapabilities, ASN_NGAP_ProtocolIE_ID_id_UESecurityCapabilities,
            ASN_NGAP_Criticality_ignore, [this](void *mem) {
                auto *sec = reinterpret_cast<ASN_NGAP_UESecurityCapabilities *>(mem); 
                asn::SetBitString(sec->nRencryptionAlgorithms, OctetString::FromHex("FFFF"));
                asn::SetBitString(sec->nRintegrityProtectionAlgorithms, OctetString::FromHex("FFFF")) ;
                asn::SetBitString(sec->eUTRAencryptionAlgorithms, OctetString::FromHex("FFFF")) ;
                asn::SetBitString(sec->eUTRAintegrityProtectionAlgorithms, OctetString::FromHex("FFFF")) ;
            });

        asn::ngap::AddProtocolIeIfUsable(
            *pdu, asn_DEF_ASN_NGAP_PDUSessionResourceToBeSwitchedDLList, ASN_NGAP_ProtocolIE_ID_id_PDUSessionResourceToBeSwitchedDLList,
            ASN_NGAP_Criticality_reject, [this](void *mem) {
                //auto &swtchpdulist = reinterpret_cast<ASN_NGAP_PDUSessionResourceToBeSwitchedDLList_t *>(mem); 
                auto *pduitem = asn::New<ASN_NGAP_PDUSessionResourceToBeSwitchedDLItem>();
                auto *PDUList = asn::New<ASN_NGAP_PathSwitchRequestIEs>();
                
                // Print PDUsession id and TEID and send as arguments
                pduitem->pDUSessionID=1;
                //std::string ss = "001f"+string_tunnel_address+"000000010009";
                std::string ss = "001fc0a81dd9000000010013";
                asn::SetOctetString(pduitem->pathSwitchRequestTransfer,OctetString::FromHex(ss));//001f7f00000f000000010009
                asn::SequenceAdd(PDUList->value.choice.PDUSessionResourceToBeSwitchedDLList,pduitem);
                *reinterpret_cast<ASN_NGAP_PDUSessionResourceToBeSwitchedDLList_t *>(mem) = PDUList->value.choice.PDUSessionResourceToBeSwitchedDLList;
                //swtchpdulist->list=PDUList->value.choice.PDUSessionResourceToBeSwitchedDLList;
                //PDUList->list.push_back(pduitem);
                // auto *supportedTa = asn::New<ASN_NGAP_SupportedTAItem>();
                // auto *ieSupportedTaList = asn::New<ASN_NGAP_NGSetupRequestIEs>();
                //asn::SequenceAdd(ieSupportedTaList->value.choice.SupportedTAList, supportedTa);

            });   
    }


    /* Encode and send the PDU */

    char errorBuffer[1024];
    size_t len;

    if (asn_check_constraints(&asn_DEF_ASN_NGAP_NGAP_PDU, pdu, errorBuffer, &len) != 0)
    {
        m_logger->err("NGAP PDU ASN constraint validation failed");
        asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
        return;
    }

    ssize_t encoded;
    uint8_t *buffer;
    if (!ngap_encode::Encode(asn_DEF_ASN_NGAP_NGAP_PDU, pdu, encoded, buffer))
        m_logger->err("NGAP APER encoding failed");
    else
    {
        auto *msg = new NmGnbSctp(NmGnbSctp::SEND_MESSAGE);
        msg->clientId = ctxtId;
        msg->stream = ue->uplinkStream;
        msg->buffer = UniqueBuffer{buffer, static_cast<size_t>(encoded)};
        m_base->sctpTask->push(msg);

        if (m_base->nodeListener)
        {
            std::string xer = ngap_encode::EncodeXer(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);
            if (xer.length() > 0)
            {
                m_base->nodeListener->onSend(app::NodeType::GNB, m_base->config->name, app::NodeType::AMF, amf_name,
                                             app::ConnectionType::NGAP, xer);
            }
        }
    }

    asn::Free(asn_DEF_ASN_NGAP_NGAP_PDU, pdu);

}

void NgapTask::receiveAmfConfigurationUpdate(int amfId, ASN_NGAP_AMFConfigurationUpdate *msg)
{
    m_logger->debug("AMF configuration update received");

    auto *amf = findAmfContext(amfId);
    if (amf == nullptr)
        return;

    bool tnlModified = false;

    auto *ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AMF_TNLAssociationToAddList);
    if (ie && ie->AMF_TNLAssociationToAddList.list.count > 0)
        tnlModified = true;

    ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AMF_TNLAssociationToRemoveList);
    if (ie && ie->AMF_TNLAssociationToRemoveList.list.count > 0)
        tnlModified = true;

    ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AMF_TNLAssociationToUpdateList);
    if (ie && ie->AMF_TNLAssociationToUpdateList.list.count > 0)
        tnlModified = true;

    // TODO: AMF TNL modification is not supported
    if (tnlModified)
    {
        m_logger->err("TNL modification is not supported, rejecting AMF configuration update");

        auto *ieCause = asn::New<ASN_NGAP_AMFConfigurationUpdateFailureIEs>();
        ieCause->id = ASN_NGAP_ProtocolIE_ID_id_Cause;
        ieCause->criticality = ASN_NGAP_Criticality_ignore;
        ieCause->value.present = ASN_NGAP_AMFConfigurationUpdateFailureIEs__value_PR_Cause;
        ngap_utils::ToCauseAsn_Ref(NgapCause::Transport_unspecified, ieCause->value.choice.Cause);

        auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_AMFConfigurationUpdateFailure>({ieCause});
        sendNgapNonUe(amfId, pdu);
    }
    else
    {
        AssignDefaultAmfConfigs(amf, msg);

        auto *ieList = asn::New<ASN_NGAP_AMFConfigurationUpdateAcknowledgeIEs>();
        ieList->id = ASN_NGAP_ProtocolIE_ID_id_AMF_TNLAssociationSetupList;
        ieList->criticality = ASN_NGAP_Criticality_ignore;
        ieList->value.present = ASN_NGAP_AMFConfigurationUpdateAcknowledgeIEs__value_PR_AMF_TNLAssociationSetupList;

        auto *pdu = asn::ngap::NewMessagePdu<ASN_NGAP_AMFConfigurationUpdateAcknowledge>({ieList});
        sendNgapNonUe(amfId, pdu);
    }
}

void NgapTask::receiveOverloadStart(int amfId, ASN_NGAP_OverloadStart *msg)
{
    m_logger->debug("AMF overload start received");

    auto *amf = findAmfContext(amfId);
    if (amf == nullptr)
        return;

    amf->overloadInfo = {};
    amf->overloadInfo.status = EOverloadStatus::OVERLOADED;

    auto *ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AMFOverloadResponse);
    if (ie && ie->OverloadResponse.present == ASN_NGAP_OverloadResponse_PR_overloadAction)
    {
        switch (ie->OverloadResponse.choice.overloadAction)
        {
        case ASN_NGAP_OverloadAction_reject_non_emergency_mo_dt:
            amf->overloadInfo.indication.action = EOverloadAction::REJECT_NON_EMERGENCY_MO_DATA;
            break;
        case ASN_NGAP_OverloadAction_reject_rrc_cr_signalling:
            amf->overloadInfo.indication.action = EOverloadAction::REJECT_SIGNALLING;
            break;
        case ASN_NGAP_OverloadAction_permit_emergency_sessions_and_mobile_terminated_services_only:
            amf->overloadInfo.indication.action = EOverloadAction::ONLY_EMERGENCY_AND_MT;
            break;
        case ASN_NGAP_OverloadAction_permit_high_priority_sessions_and_mobile_terminated_services_only:
            amf->overloadInfo.indication.action = EOverloadAction::ONLY_HIGH_PRI_AND_MT;
            break;
        default:
            m_logger->warn("AMF overload action [%d] could not understand",
                           (int)ie->OverloadResponse.choice.overloadAction);
            break;
        }
    }

    ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_AMFTrafficLoadReductionIndication);
    if (ie)
        amf->overloadInfo.indication.loadReductionPerc = static_cast<int>(ie->TrafficLoadReductionIndication);

    ie = asn::ngap::GetProtocolIe(msg, ASN_NGAP_ProtocolIE_ID_id_OverloadStartNSSAIList);
    if (ie)
    {
        // TODO
        /*asn::ForeachItem(ie->OverloadStartNSSAIList, [](auto &item) {
            item.sliceOverloadList;
        });*/
    }
}

void NgapTask::receiveOverloadStop(int amfId, ASN_NGAP_OverloadStop *msg)
{
    m_logger->debug("AMF overload stop received");

    // TODO
}

} // namespace nr::gnb