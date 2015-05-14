/*
 * Copyright (c) 2012 Qualcomm Atheros, Inc.
 * All Rights Reserved.
 * Qualcomm Atheros Confidential and Proprietary.
 */



#ifndef _API_ACCESS_H
#define _API_ACCESS_H

#ifdef __cplusplus
extern "C" {
#endif                          /* __cplusplus */

    sw_api_func_t *
    sw_api_func_find(a_uint32_t api_id);

    sw_api_param_t *
    sw_api_param_find(a_uint32_t api_id);

    a_uint32_t
    sw_api_param_nums(a_uint32_t api_id);

    sw_error_t
    sw_api_get(sw_api_t *sw_api);

#ifdef __cplusplus
}
#endif                          /* __cplusplus */
#endif                          /* _API_ACCESS_H */
